/**
 * nrf24_sniffer.c — Firmware principal para CC1352P7
 *
 * Captura paquetes Enhanced ShockBurst (nRF24L01+) en modo promiscuo
 * o dirigido, y los envía por UART en formato legible/parseable por Python.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  COMPILACIÓN: requiere TI SimpleLink CC13xx/CC26xx SDK ≥ 7.10      │
 * │  Ver README.md para instrucciones de build completas                │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Protocolo UART (115200 8N1):
 *   Líneas del firmware → host:
 *     [INIT] ch=076 freq=2476MHz rate=1M mode=PROMISC
 *     [PKT]  ch=076 rssi=-055 len=37 raw=AABBCC...
 *     [ESB]  ch=076 rssi=-055 addr=E7E7E7E7E7 plen=8 pid=0 noack=0 pld=... crc=OK
 *     [ACK]  ch=076 rssi=-055 addr=E7E7E7E7E7 empty
 *     [SCAN] ch=076 active=1 pkts=3 rssi_max=-045
 *     [ERR]  descripción
 *
 *   Comandos host → firmware:
 *     CH:076\r\n            → cambiar canal (0-125)
 *     CH:SCAN\r\n           → modo escaneo (ciclos por todos los canales)
 *     ADDR:E7E7E7E7E7\r\n   → modo dirigido con address dada
 *     MODE:PROMISC\r\n      → modo promiscuo
 *     RATE:1M\r\n           → 1 Mbps
 *     RATE:2M\r\n           → 2 Mbps
 *     RATE:250K\r\n         → 250 kbps
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

/* TI SimpleLink SDK */
#include <ti/drivers/rf/RF.h>
#include <ti/drivers/UART2.h>
#include <ti/drivers/Board.h>

/* NoRTOS + DPL */
#include <NoRTOS.h>
#include <ti/drivers/dpl/ClockP.h>

/* Device-specific */
#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/rf_prop_mailbox.h>
#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/rf_prop_cmd.h>
#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/rf_data_entry.h>
#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/rfc.h>

/* Nuestros headers */
#include "smartrf_settings.h"
#include "nrf24_esb.h"
#include "ti_drivers_config.h"

/* ── Configuración ─────────────────────────────────────────────────────────── */

#define NRF24_UART_BAUD         115200u
#define NRF24_RX_BUF_LEN        64u     /* bytes para CMD_PROP_RX_ADV */
#define NRF24_CMD_BUF_LEN       32u     /* bytes para comandos UART entrantes */
#define NRF24_DEFAULT_CHANNEL   76u     /* 2476 MHz — default muchas libs Arduino */
#define NRF24_SCAN_DWELL_MS     20u     /* ms por canal en modo SCAN */
#define NRF24_MAX_CHANNELS      126u    /* canales 0–125 */

/* Task RTOS */
#define NRF24_TASK_STACK_SIZE   2048u
#define NRF24_CMD_TASK_STACK    1024u

/* ── Tipos internos ─────────────────────────────────────────────────────────── */

typedef enum {
    MODE_PROMISC  = 0,  /* modo promiscuo: sync word = 0xAAAAAAAA */
    MODE_DIRECTED = 1,  /* modo dirigido: sync word = address del target */
    MODE_SCAN     = 2,  /* escaneo secuencial de canales 0-125 */
} sniffer_mode_t;

typedef struct {
    sniffer_mode_t mode;
    uint8_t        channel;          /* canal actual 0-125 */
    nrf24_rate_t   rate;             /* 1M / 2M / 250K */
    uint8_t        target_addr[5];   /* address en modo DIRECTED */
    uint8_t        target_aw;        /* address width en modo DIRECTED */
} sniffer_state_t;

/* ── Variables globales ─────────────────────────────────────────────────────── */

static UART2_Handle  g_uart;
static RF_Object     g_rfObject;
static RF_Handle     g_rfHandle;
static sniffer_state_t g_state = {
    .mode    = MODE_PROMISC,
    .channel = NRF24_DEFAULT_CHANNEL,
    .rate    = NRF24_RATE_1MBPS,
    .target_aw = 5,
};

/* Buffer de recepción RF (shared con RF core DMA) */
static uint8_t g_rxBuf[NRF24_RX_BUF_LEN]  __attribute__((aligned(4)));

/* ── DataQueue para CMD_PROP_RX_ADV ─────────────────────────────────────────── *
 * CMD_PROP_RX_ADV requiere una DataQueue con al menos una entrada para que
 * el RF core tenga donde guardar el paquete recibido. Sin esto pQueue=NULL
 * implica que ningún paquete se almacena y rx_one_packet() nunca recibe nada.
 * Se usa DATA_ENTRY_TYPE_PTR apuntando a g_rxBuf (paquete fijo 37 bytes).     */
static rfc_dataEntryPointer_t g_rxEntry  __attribute__((aligned(4)));
static dataQueue_t            g_rxQueue;
/* Buffer de transmisión (frame ESB construido por esb_build_frame) */
static uint8_t g_txBuf[ESB_MAX_FRAME_LEN]  __attribute__((aligned(4)));
/* Buffer de entrada UART para comandos */
static char    g_cmdBuf[NRF24_CMD_BUF_LEN];
/* Recepción UART asíncrona (callback en NoRTOS) */
static volatile bool   g_cmdReady = false;
static volatile char   g_rxChar;
static size_t          g_cmdIdx = 0;

/* ── Helpers UART ───────────────────────────────────────────────────────────── */

/**
 * uart_puts() — Envía string por UART (bloqueante, sin formateo).
 */
static void uart_puts(const char *s)
{
    size_t len = strlen(s);
    UART2_write(g_uart, s, len, NULL);
}

/**
 * uart_printf() — Envía por UART con formato printf().
 * Buffer interno 128 bytes — no usar para payloads grandes.
 */
static void uart_printf(const char *fmt, ...)
{
    char buf[128];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    uart_puts(buf);
}

/* ── Inicialización de RF ───────────────────────────────────────────────────── */

/**
 * rf_init() — Abre el driver RF y envía CMD_PROP_RADIO_DIV_SETUP.
 * Debe llamarse una vez en startup.
 */
static bool rf_init(void)
{
    RF_Params rfParams;
    RF_Params_init(&rfParams);

    g_rfHandle = RF_open(&g_rfObject,
                          &RF_prop,             /* RF_Mode generado por SysConfig */
                          (RF_RadioSetup *)&RF_nrf24_cmdPropRadioDivSetup_1M,
                          &rfParams);
    if (g_rfHandle == NULL) {
        uart_puts("[ERR] RF_open failed\r\n");
        return false;
    }
    return true;
}

/**
 * rf_set_channel() — Cambia el canal RF en tiempo real.
 * Para el CC1352P7 en modo propietario 2.4 GHz se modifica centerFreq
 * y se re-ejecuta CMD_PROP_RADIO_DIV_SETUP.
 */
static bool rf_set_channel(uint8_t channel)
{
    if (channel > 125) { return false; }

    /* Actualizar el struct de setup en RAM */
    RF_nrf24_update_channel(channel);

    /* Re-ejecutar el setup para aplicar el nuevo canal */
    RF_runCmd(g_rfHandle,
              (RF_Op *)&RF_nrf24_cmdPropRadioDivSetup_1M,
              RF_PriorityNormal, NULL, 0);
    return true;
}

/**
 * rf_set_sync_word() — Cambia el sync word del CMD_PROP_RX_ADV.
 * Modo promiscuo: 0xAAAAAAAA
 * Modo dirigido:  address del target (4/5 bytes)
 */
static void rf_set_sync_word_promisc(void)
{
    RF_nrf24_cmdPropRxAdv.syncWord0    = 0xAAAAAAAAUL;
    /* syncWordLen is implicit: syncWord0 is always 32 bits */
}

static void rf_set_sync_word_directed(const uint8_t *addr, uint8_t aw)
{
    /* Sync word = preamble (1 byte) + primeros 3 bytes de addr */
    uint8_t preamble = esb_preamble_for_addr(addr);
    RF_nrf24_cmdPropRxAdv.syncWord0 =
        ((uint32_t)preamble   << 24) |
        ((uint32_t)addr[0]    << 16) |
        ((uint32_t)addr[1]    <<  8) |
        ((uint32_t)addr[2]);
    /* syncWordLen is implicit: syncWord0 is always 32 bits */
    (void)aw; /* se podría ampliar a 40 bits para mayor selectividad */
}

/* ── Transmisión TX ──────────────────────────────────────────────────────────── */

/**
 * rf_tx_frame() — Transmite un frame ESB pre-compilado.
 *
 * El frame en tx_buf ya debe contener: addr + PCF + payload + CRC
 * (construido con esb_build_frame). NO incluir preamble.
 *
 * El sync word del CMD_PROP_TX se ajusta automáticamente según el primer
 * byte del frame (dirección), para que el preamble generado sea correcto.
 *
 * @param tx_buf    Puntero al frame ESB listo para TX
 * @param tx_len    Longitud del frame en bytes
 * @return true si CMD_PROP_TX terminó con PROP_DONE_OK
 */
static bool rf_tx_frame(const uint8_t *tx_buf, uint8_t tx_len)
{
    if (!tx_buf || tx_len == 0u || tx_len > ESB_MAX_FRAME_LEN) { return false; }

    /* Ajustar sync word TX según la dirección (primer byte del frame) */
    uint8_t preamble = esb_preamble_for_addr(tx_buf); /* usa el primer byte */
    RF_nrf24_cmdPropTx.syncWord = ((uint32_t)preamble   << 24) |
                                   ((uint32_t)tx_buf[0]  << 16) |
                                   ((uint32_t)tx_buf[1]  <<  8) |
                                   ((uint32_t)tx_buf[2]);

    /* Copiar frame al buffer alineado y configurar el puntero */
    memcpy(g_txBuf, tx_buf, tx_len);
    RF_nrf24_cmdPropTx.pPkt    = g_txBuf;
    RF_nrf24_cmdPropTx.pktLen  = tx_len;
    RF_nrf24_cmdPropTx.status  = 0;

    RF_runCmd(g_rfHandle,
              (RF_Op *)&RF_nrf24_cmdPropTx,
              RF_PriorityNormal, NULL, 0);

    return (RF_nrf24_cmdPropTx.status == PROP_DONE_OK);
}

/* ── Recepción y parseo de un frame ─────────────────────────────────────────── */

/**
 * rx_one_packet() — Espera y recibe un frame crudo del radio.
 *
 * Configura g_rxBuf como destino del CMD_PROP_RX_ADV y ejecuta el
 * comando RF de forma bloqueante (hasta timeout o dato recibido).
 *
 * @param rssi_out   Puntero donde guardar el RSSI (dBm)
 * @param len_out    Bytes recibidos
 * @param timeout_ms Timeout en ms (0 = infinito)
 * @return true si se recibió un frame antes del timeout
 */
static bool rx_one_packet(int8_t *rssi_out, uint8_t *len_out, uint32_t timeout_ms)
{
    static rfc_propRxOutput_t rxStats;

    /* ── Configurar DataEntry apuntando a g_rxBuf ────────────────────────────
     * CMD_PROP_RX_ADV exige una DataQueue válida para almacenar paquetes.
     * Usamos una entrada tipo PTR (tipo 2) de tamaño fijo = maxPktLen (37 B).
     * La entrada es circular (pNextEntry → sí misma) para que el comando
     * pueda reutilizarla dentro de la misma ventana de timeout si bRepeatOk=1.
     * Con bRepeatOk=0 (smartrf_settings.c) el comando para tras el 1er paquete
     * y esto no es necesario, pero por robustez se mantiene circular.          */
    memset(&g_rxEntry, 0, sizeof(g_rxEntry));
    g_rxEntry.status          = DATA_ENTRY_PENDING;
    g_rxEntry.config.type     = DATA_ENTRY_TYPE_PTR;
    g_rxEntry.config.lenSz    = 0;               /* sin prefijo de longitud */
    g_rxEntry.length          = NRF24_RX_BUF_LEN;
    g_rxEntry.pData           = g_rxBuf;
    g_rxEntry.pNextEntry      = (uint8_t *)&g_rxEntry; /* circular: 1 entrada */

    g_rxQueue.pCurrEntry = (uint8_t *)&g_rxEntry;
    g_rxQueue.pLastEntry = NULL;

    memset(&rxStats, 0, sizeof(rxStats));
    memset(g_rxBuf,  0, NRF24_RX_BUF_LEN);

    /* pQueue → DataQueue con los datos; pOutput → estadísticas (RSSI, contadores) */
    RF_nrf24_cmdPropRxAdv.pQueue  = &g_rxQueue;
    RF_nrf24_cmdPropRxAdv.pOutput = (uint8_t *)&rxStats;

    /* Trigger = NOW; endTrigger = TRIG_REL_START con timeout */
    if (timeout_ms > 0) {
        RF_nrf24_cmdPropRxAdv.endTrigger.triggerType = TRIG_REL_START;
        RF_nrf24_cmdPropRxAdv.endTime = (uint32_t)(timeout_ms * 4000u); /* 4 µs ticks */
    } else {
        RF_nrf24_cmdPropRxAdv.endTrigger.triggerType = TRIG_NEVER;
        RF_nrf24_cmdPropRxAdv.endTime = 0;
    }

    RF_runCmd(g_rfHandle,
              (RF_Op *)&RF_nrf24_cmdPropRxAdv,
              RF_PriorityNormal, NULL, 0);

    uint16_t cmd_status = RF_nrf24_cmdPropRxAdv.status;
    if (cmd_status == PROP_DONE_OK || cmd_status == PROP_DONE_ENDED) {
        *rssi_out = rxStats.lastRssi;
        if (g_rxEntry.status == DATA_ENTRY_FINISHED) {
            *len_out = RF_nrf24_cmdPropRxAdv.maxPktLen; /* fijo: 37 bytes */
            return true;
        }
    }
    *len_out = 0;
    return false;
}

/**
 * process_and_report() — Parsea g_rxBuf como ESB y envía al host por UART.
 */
static void process_and_report(uint8_t channel, int8_t rssi, uint8_t raw_len)
{
    /* 1. Reportar paquete crudo siempre */
    {
        char hex_buf[75 + 1]; /* 37 bytes × 2 chars/byte = 74 chars + '\0' */
        static const char hx[] = "0123456789ABCDEF";
        uint16_t j = 0;
        for (uint8_t i = 0; i < raw_len && i < NRF24_RX_BUF_LEN; i++) {
            hex_buf[j++] = hx[g_rxBuf[i] >> 4];
            hex_buf[j++] = hx[g_rxBuf[i] & 0xFu];
        }
        hex_buf[j] = '\0';
        uart_printf("[PKT] ch=%03u rssi=%+04d len=%u raw=%s\r\n",
                    channel, (int)rssi, raw_len, hex_buf);
    }

    /* 2. Intentar parsear como ESB promiscuo */
    nrf24_frame_t frame;

    /* Buscar el inicio real del frame saltando los bytes de sync/preamble:
     * En g_rxBuf el CC1352P7 entrega el payload SIN el sync word (el RF core
     * usa el sync word para sincronizar pero no lo incluye en el buffer).
     * g_rxBuf[0] = primer byte de ADDRESS (tras el preamble).               */
    bool parsed;
    if (g_state.mode == MODE_DIRECTED) {
        parsed = esb_parse(g_rxBuf, raw_len, g_state.target_aw,
                            NRF24_CRC_1BYTE, &frame);
        if (!parsed) {
            parsed = esb_parse(g_rxBuf, raw_len, g_state.target_aw,
                                NRF24_CRC_2BYTE, &frame);
        }
    } else {
        parsed = esb_parse_promiscuous(g_rxBuf, raw_len, &frame);
    }

    if (!parsed) { return; }

    /* 3. Reportar frame ESB decodificado */
    char addr_str[11]; /* 5 bytes × 2 + '\0' */
    esb_addr_to_hex(&frame, addr_str);

    if (frame.is_ack) {
        uart_printf("[ACK] ch=%03u rssi=%+04d addr=%s empty\r\n",
                    channel, (int)rssi, addr_str);
        return;
    }

    /* Payload en hex */
    char pld_str[65]; /* 32 bytes × 2 + '\0' */
    static const char hx[] = "0123456789ABCDEF";
    uint16_t j = 0;
    for (uint8_t i = 0; i < frame.payload_len; i++) {
        pld_str[j++] = hx[frame.payload[i] >> 4];
        pld_str[j++] = hx[frame.payload[i] & 0xFu];
    }
    pld_str[j] = '\0';

    uart_printf("[ESB] ch=%03u rssi=%+04d addr=%s plen=%u pid=%u noack=%u pld=%s crc=%s\r\n",
                channel, (int)rssi, addr_str,
                frame.payload_len, frame.pid, (uint8_t)frame.no_ack,
                pld_str, frame.valid ? "OK" : "FAIL");
}

/* ── Callback de UART2 (NoRTOS: acumula bytes, señala comando completo) ────── */

static void uart_read_callback(UART2_Handle handle, void *buf, size_t count,
                                void *userArg, int_fast16_t status)
{
    if (status == UART2_STATUS_SUCCESS && count > 0) {
        char c = g_rxChar;
        if (c == '\r' || c == '\n') {
            if (g_cmdIdx > 0) {
                g_cmdBuf[g_cmdIdx] = '\0';
                g_cmdReady = true;
                return; /* esperar a que main() procese el comando */
            }
        } else if (g_cmdIdx < NRF24_CMD_BUF_LEN - 1) {
            g_cmdBuf[g_cmdIdx++] = (char)toupper((int)c);
        }
    }
    /* Solicitar siguiente byte */
    UART2_read(handle, (void *)&g_rxChar, 1, NULL);
}

/* ── Tarea de comandos UART ──────────────────────────────────────────────────── */

/**
 * parse_hex_addr() — Parsea string "E7E7E7E7E7" a bytes.
 * @param s       String hexadecimal (10 chars para 5 bytes)
 * @param out     Buffer de salida (5 bytes)
 * @param out_aw  Address width (longitud detectada, 3-5)
 * @return true si el parse fue exitoso
 */
static bool parse_hex_addr(const char *s, uint8_t *out, uint8_t *out_aw)
{
    uint8_t len = (uint8_t)strlen(s);
    if (len < 6 || len > 10 || (len & 1u)) { return false; }
    *out_aw = (uint8_t)(len / 2);
    for (uint8_t i = 0; i < *out_aw; i++) {
        uint8_t hi = s[i * 2];
        uint8_t lo = s[i * 2 + 1];
        hi = (hi >= 'A') ? (hi - 'A' + 10) : (hi - '0');
        lo = (lo >= 'A') ? (lo - 'A' + 10) : (lo - '0');
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/**
 * parse_hex_bytes() — Parsea string hex a buffer de bytes.
 * @param s       String hexadecimal (pares de chars)
 * @param out     Buffer de salida
 * @param max_len Tamaño máximo del buffer de salida
 * @param out_len Bytes escritos en out
 * @return true si el parse fue exitoso
 */
static bool parse_hex_bytes(const char *s, uint8_t *out,
                             uint8_t max_len, uint8_t *out_len)
{
    uint8_t slen = (uint8_t)strlen(s);
    if (slen == 0u || (slen & 1u)) { return false; }
    *out_len = (uint8_t)(slen / 2);
    if (*out_len > max_len) { return false; }
    for (uint8_t i = 0; i < *out_len; i++) {
        uint8_t hi = (uint8_t)s[i * 2];
        uint8_t lo = (uint8_t)s[i * 2 + 1];
        hi = (hi >= 'A') ? (hi - 'A' + 10u) : (hi - '0');
        lo = (lo >= 'A') ? (lo - 'A' + 10u) : (lo - '0');
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void handle_command(void)
{
            /* ── Parsear comando ── */
            if (strncmp(g_cmdBuf, "CH:", 3) == 0) {
                if (strcmp(g_cmdBuf + 3, "SCAN") == 0) {
                    g_state.mode = MODE_SCAN;
                    uart_puts("[CMD] mode=SCAN\r\n");
                } else {
                    uint8_t ch = (uint8_t)atoi(g_cmdBuf + 3);
                    if (ch <= 125) {
                        g_state.channel = ch;
                        g_state.mode    = MODE_PROMISC;
                        rf_set_channel(ch);
                        uart_printf("[CMD] ch=%03u freq=%uMHz\r\n",
                                    ch, (unsigned)(2400u + ch));
                    }
                }

            } else if (strncmp(g_cmdBuf, "ADDR:", 5) == 0) {
                uint8_t addr[5];
                uint8_t aw = 5;
                if (parse_hex_addr(g_cmdBuf + 5, addr, &aw)) {
                    memcpy(g_state.target_addr, addr, aw);
                    g_state.target_aw = aw;
                    g_state.mode = MODE_DIRECTED;
                    rf_set_sync_word_directed(addr, aw);
                    char hex[11];
                    static const char hx[] = "0123456789ABCDEF";
                    for (uint8_t i = 0; i < aw; i++) {
                        hex[i*2]   = hx[addr[i] >> 4];
                        hex[i*2+1] = hx[addr[i] & 0xFu];
                    }
                    hex[aw*2] = '\0';
                    uart_printf("[CMD] mode=DIRECTED addr=%s aw=%u\r\n", hex, aw);
                }

            } else if (strcmp(g_cmdBuf, "MODE:PROMISC") == 0) {
                g_state.mode = MODE_PROMISC;
                rf_set_sync_word_promisc();
                uart_puts("[CMD] mode=PROMISC\r\n");

            } else if (strcmp(g_cmdBuf, "RATE:1M") == 0) {
                g_state.rate = NRF24_RATE_1MBPS;
                uart_puts("[CMD] rate=1M (re-flash required for RF change)\r\n");

            } else if (strcmp(g_cmdBuf, "RATE:2M") == 0) {
                g_state.rate = NRF24_RATE_2MBPS;
                uart_puts("[CMD] rate=2M (re-flash required for RF change)\r\n");

            } else if (strcmp(g_cmdBuf, "RATE:250K") == 0) {
                g_state.rate = NRF24_RATE_250KBPS;
                uart_puts("[CMD] rate=250K (re-flash required for RF change)\r\n");

            /* ── TX:ADDR_HEX:PAYLOAD_HEX — spoof / inyección MouseJack ── */
            } else if (strncmp(g_cmdBuf, "TX:", 3) == 0) {
                /*
                 * Formato: TX:ADDR:PAYLOAD_HEX
                 *   ADDR       = 6-10 chars hex (3-5 bytes de dirección)
                 *   PAYLOAD_HEX = 0-64 chars hex (0-32 bytes de payload)
                 * Transmite un frame ESB construido con CRC-2 y NO_ACK=0.
                 */
                const char *p = g_cmdBuf + 3;
                const char *colon = strchr(p, ':');
                if (!colon) {
                    uart_puts("[TX] ERR bad format (TX:ADDR:PAYLOAD)\r\n");
                } else {
                    /* separar addr y payload */
                    char addr_str[11];
                    uint8_t addr_len = (uint8_t)(colon - p);
                    if (addr_len < 6u || addr_len > 10u) {
                        uart_puts("[TX] ERR addr length\r\n");
                    } else {
                        memcpy(addr_str, p, addr_len);
                        addr_str[addr_len] = '\0';

                        uint8_t addr[5]; uint8_t aw = 5;
                        if (!parse_hex_addr(addr_str, addr, &aw)) {
                            uart_puts("[TX] ERR addr parse\r\n");
                        } else {
                            uint8_t payload[ESB_MAX_PAYLOAD_LEN];
                            uint8_t plen = 0;
                            bool payload_ok = true;
                            if (*(colon + 1) != '\0') {
                                payload_ok = parse_hex_bytes(colon + 1, payload,
                                                              ESB_MAX_PAYLOAD_LEN, &plen);
                            }
                            if (!payload_ok) {
                                uart_puts("[TX] ERR payload parse\r\n");
                            } else {
                                uint8_t  frame[ESB_MAX_FRAME_LEN];
                                static uint8_t s_tx_pid = 0;
                                uint16_t flen = esb_build_frame(addr, aw,
                                                                 plen ? payload : NULL,
                                                                 plen, s_tx_pid, false,
                                                                 NRF24_CRC_2BYTE, frame);
                                s_tx_pid = (uint8_t)((s_tx_pid + 1u) & 0x03u);
                                if (flen == 0u) {
                                    uart_puts("[TX] ERR build frame\r\n");
                                } else if (rf_tx_frame(frame, (uint8_t)flen)) {
                                    uart_printf("[TX] OK addr=%s plen=%u flen=%u\r\n",
                                                addr_str, plen, (unsigned)flen);
                                } else {
                                    uart_puts("[TX] ERR rf_tx failed\r\n");
                                }
                            }
                        }
                    }
                }

            /* ── REPLAY:RAW_HEX — retransmitir frame crudo capturado ── */
            } else if (strncmp(g_cmdBuf, "REPLAY:", 7) == 0) {
                /*
                 * Formato: REPLAY:RAW_HEX
                 *   RAW_HEX = frame ESB completo en hex (addr+PCF+payload+CRC)
                 * Retransmite los bytes exactos sin modificación (replay attack).
                 */
                uint8_t raw[ESB_MAX_FRAME_LEN];
                uint8_t rlen = 0;
                if (!parse_hex_bytes(g_cmdBuf + 7, raw, ESB_MAX_FRAME_LEN, &rlen)) {
                    uart_puts("[REPLAY] ERR parse\r\n");
                } else if (rf_tx_frame(raw, rlen)) {
                    uart_printf("[REPLAY] OK len=%u\r\n", (unsigned)rlen);
                } else {
                    uart_puts("[REPLAY] ERR rf_tx failed\r\n");
                }
            }
}

/* ── Entrypoint ────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Inicializar el BSP (Board Support Package) de TI */
    Board_init();

    /* Inicializar NoRTOS (DPL bare-metal) */
    NoRTOS_start();

    /* Inicializar UART2 a 115200 baud (callback para RX, bloqueante para TX) */
    UART2_Params uartParams;
    UART2_Params_init(&uartParams);
    uartParams.baudRate  = NRF24_UART_BAUD;
    uartParams.readMode  = UART2_Mode_CALLBACK;
    uartParams.readCallback = uart_read_callback;
    uartParams.writeMode = UART2_Mode_BLOCKING;
    g_uart = UART2_open(CONFIG_UART2_0, &uartParams);

    /* Arrancar recepción asíncrona de primer byte */
    UART2_read(g_uart, (void *)&g_rxChar, 1, NULL);

    /* Inicializar RF */
    if (!rf_init()) {
        uart_puts("[ERR] RF init failed, halting\r\n");
        while (1) { ClockP_usleep(1000000); }
    }

    uart_puts("===== nRF24L01+ Sniffer (CC1352P7) =====\r\n");
    uart_printf("[INIT] ch=%03u freq=%uMHz rate=%s mode=%s\r\n",
                g_state.channel,
                (unsigned)(2400u + g_state.channel),
                g_state.rate == NRF24_RATE_1MBPS   ? "1M" :
                g_state.rate == NRF24_RATE_2MBPS   ? "2M" : "250K",
                g_state.mode == MODE_PROMISC  ? "PROMISC" :
                g_state.mode == MODE_DIRECTED ? "DIRECTED" : "SCAN");

    rf_set_sync_word_promisc();
    rf_set_channel(g_state.channel);

    /* ── Super-loop NoRTOS ─────────────────────────────────────────────────── */
    while (1) {
        /* Procesar comando UART pendiente */
        if (g_cmdReady) {
            handle_command();
            g_cmdReady = false;
            g_cmdIdx   = 0;
            UART2_read(g_uart, (void *)&g_rxChar, 1, NULL);
        }

        if (g_state.mode == MODE_SCAN) {
            /* Ciclar por todos los canales, 20 ms cada uno */
            for (uint8_t ch = 0; ch < NRF24_MAX_CHANNELS; ch++) {
                /* Atender comandos entre canales */
                if (g_cmdReady) {
                    handle_command();
                    g_cmdReady = false;
                    g_cmdIdx   = 0;
                    UART2_read(g_uart, (void *)&g_rxChar, 1, NULL);
                    if (g_state.mode != MODE_SCAN) { break; }
                }

                rf_set_channel(ch);
                uint8_t pkts = 0;
                int8_t  rssi_max = -120;

                uint32_t t_start    = ClockP_getSystemTicks();
                uint32_t tick_period = ClockP_getSystemTickPeriod();
                uint32_t dwell_ticks = (NRF24_SCAN_DWELL_MS * 1000u) / tick_period;

                while ((ClockP_getSystemTicks() - t_start) < dwell_ticks) {
                    int8_t  rssi  = -120;
                    uint8_t rlen  = 0;
                    if (rx_one_packet(&rssi, &rlen, NRF24_SCAN_DWELL_MS)) {
                        pkts++;
                        if (rssi > rssi_max) { rssi_max = rssi; }
                        process_and_report(ch, rssi, rlen);
                    }
                }
                uart_printf("[SCAN] ch=%03u active=%u pkts=%u rssi_max=%+04d\r\n",
                            ch, pkts > 0 ? 1u : 0u, pkts, (int)rssi_max);
            }

        } else {
            /* Modo PROMISC o DIRECTED: recibir en bucle */
            int8_t  rssi = -120;
            uint8_t rlen = 0;
            if (rx_one_packet(&rssi, &rlen, 1000u /* 1 s timeout */)) {
                process_and_report(g_state.channel, rssi, rlen);
            }
        }
    }
}
