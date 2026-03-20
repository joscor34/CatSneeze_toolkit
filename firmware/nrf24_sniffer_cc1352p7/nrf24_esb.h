/**
 * nrf24_esb.h — Parser portable del protocolo Enhanced ShockBurst (ESB)
 *
 * Sin dependencias externas. Funciona tanto en el firmware CC1352P7
 * como en cualquier implementación C en host.
 *
 * Referencia: nRF24L01+ Product Specification 1.0, §7 (Air Interface)
 */
#ifndef NRF24_ESB_H_
#define NRF24_ESB_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constantes del protocolo ──────────────────────────────────────────────── */

#define ESB_MAX_PAYLOAD_LEN   32      /* bytes */
#define ESB_PREAMBLE_1MBPS    0xAA    /* si MSB addr == 1  */
#define ESB_PREAMBLE_ALT      0x55    /* si MSB addr == 0  */
#define ESB_ADDR_WIDTH_MIN    3
#define ESB_ADDR_WIDTH_MAX    5
#define ESB_PCF_BYTES         2       /* 9 bits PCF → empaquetado en 2 bytes */
#define ESB_CRC8_POLY         0x07U
#define ESB_CRC8_INIT         0xFFU
#define ESB_CRC16_POLY        0x1021U /* CCITT-16, equivalente a Nordic CRC-16 */
#define ESB_CRC16_INIT        0xFFFFU

/* Máximo frame ESB = preamble(1) + addr(5) + PCF(2) + payload(32) + CRC(2) */
#define ESB_MAX_FRAME_LEN     42

/* ── Tipos ─────────────────────────────────────────────────────────────────── */

/** Tasa de datos del nRF24L01+ */
typedef enum {
    NRF24_RATE_1MBPS   = 0,
    NRF24_RATE_2MBPS   = 1,
    NRF24_RATE_250KBPS = 2,
} nrf24_rate_t;

/** Longitud del CRC */
typedef enum {
    NRF24_CRC_NONE  = 0,
    NRF24_CRC_1BYTE = 1,
    NRF24_CRC_2BYTE = 2,
} nrf24_crc_t;

/** Resultado de parseo de un frame ESB */
typedef struct {
    bool        valid;                          /* frame válido (CRC correcto) */
    uint8_t     addr_width;                     /* 3, 4 o 5 */
    uint8_t     addr[ESB_ADDR_WIDTH_MAX];       /* dirección (MSB primero) */
    uint8_t     payload_len;                    /* 0–32 bytes */
    uint8_t     pid;                            /* 0–3, Packet ID */
    bool        no_ack;                         /* 1 = sin ACK requerido */
    uint8_t     payload[ESB_MAX_PAYLOAD_LEN];   /* datos */
    nrf24_crc_t crc_type;                       /* CRC detectado */
    uint16_t    crc_received;                   /* valor CRC del frame */
    uint16_t    crc_computed;                   /* valor CRC calculado */
    bool        is_ack;                         /* ACK vacío (plen=0, no_ack=0) */
} nrf24_frame_t;

/* ── Funciones internas (CRC) ───────────────────────────────────────────────── */

/**
 * CRC-8 para Enhanced ShockBurst.
 * Polinomio: x^8 + x^2 + x + 1 (0x07), IV = 0xFF, MSB primero.
 * El CRC cubre: address + PCF bytes + payload.
 */
static inline uint8_t esb_crc8(const uint8_t *data, uint16_t len)
{
    uint8_t crc = ESB_CRC8_INIT;
    for (uint16_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t b = 0; b < 8; b++) {
            if (crc & 0x80U) {
                crc = (uint8_t)((crc << 1) ^ (uint8_t)(ESB_CRC8_POLY));
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/**
 * CRC-16 CCITT para Enhanced ShockBurst.
 * Polinomio: 0x1021, IV = 0xFFFF, MSB primero.
 */
static inline uint16_t esb_crc16(const uint8_t *data, uint16_t len)
{
    uint16_t crc = ESB_CRC16_INIT;
    for (uint16_t i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (uint8_t b = 0; b < 8; b++) {
            if (crc & 0x8000U) {
                crc = (uint16_t)((crc << 1) ^ ESB_CRC16_POLY);
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/* ── Parser principal ───────────────────────────────────────────────────────── */

/**
 * esb_parse() — Intenta parsear un buffer crudo como frame ESB.
 *
 * @param buf         Buffer crudo recibido del radio (sin preamble, empieza en addr)
 * @param buf_len     Longitud del buffer (bytes)
 * @param addr_width  Ancho de dirección a probar: 3, 4 o 5
 * @param crc_type    Tipo de CRC esperado (NONE/1BYTE/2BYTE)
 * @param out         Frame resultado
 * @return true si el frame es válido (CRC correcto o crc_type==NONE)
 *
 * Diseño deliberado: no asigna memoria dinámica, seguro para uso en firmware.
 */
static inline bool esb_parse(const uint8_t  *buf,
                              uint16_t        buf_len,
                              uint8_t         addr_width,
                              nrf24_crc_t     crc_type,
                              nrf24_frame_t  *out)
{
    if (!buf || !out) { return false; }
    if (addr_width < ESB_ADDR_WIDTH_MIN || addr_width > ESB_ADDR_WIDTH_MAX) {
        return false;
    }

    /* Longitud mínima: addr + PCF(2 bytes) + CRC */
    uint8_t crc_len = (crc_type == NRF24_CRC_2BYTE) ? 2u :
                      (crc_type == NRF24_CRC_1BYTE)  ? 1u : 0u;
    uint16_t min_len = (uint16_t)(addr_width + ESB_PCF_BYTES + crc_len);
    if (buf_len < min_len) { return false; }

    memset(out, 0, sizeof(*out));
    out->addr_width = addr_width;
    out->crc_type   = crc_type;

    /* Copiar dirección (MSB primero) */
    memcpy(out->addr, buf, addr_width);

    /*
     * PCF: 9 bits empaquetados en los 2 bytes que siguen a la dirección.
     * Layout bit-a-bit (MSB of buf[addr_width] = bit 8 del PCF):
     *   byte0: bits [8:1]  = {payload_len[5:0], pid[1]}
     *   byte1: bits [0]    = {pid[0]} en posición bit 7, no_ack en bit 6
     *
     * Conforme a la especificación Nordic §7.4:
     *   PCF[8:3] = payload length (6 bits)
     *   PCF[2:1] = PID (2 bits)
     *   PCF[0]   = NO_ACK
     *
     * Los 9 bits se transmiten MSB-first, rellenando el byte2 con ceros.
     */
    uint16_t pcf_raw = ((uint16_t)buf[addr_width] << 1) |
                       (buf[addr_width + 1] >> 7);
    out->payload_len = (uint8_t)((pcf_raw >> 3) & 0x3FU);
    out->pid         = (uint8_t)((pcf_raw >> 1) & 0x03U);
    out->no_ack      = (bool)   (pcf_raw & 0x01U);

    /* Validar longitud del payload */
    if (out->payload_len > ESB_MAX_PAYLOAD_LEN) { return false; }

    /* Verificar que el buffer tiene suficientes bytes */
    uint16_t expected = (uint16_t)(addr_width + ESB_PCF_BYTES + out->payload_len + crc_len);
    if (buf_len < expected) { return false; }

    /* Copiar payload */
    uint16_t pld_off = (uint16_t)(addr_width + ESB_PCF_BYTES);
    memcpy(out->payload, buf + pld_off, out->payload_len);

    /* Verificar CRC sobre: addr + PCF bytes + payload */
    uint16_t crc_data_len = (uint16_t)(addr_width + ESB_PCF_BYTES + out->payload_len);

    if (crc_type == NRF24_CRC_1BYTE) {
        out->crc_received = buf[pld_off + out->payload_len];
        out->crc_computed = esb_crc8(buf, crc_data_len);
        out->valid = (out->crc_received == out->crc_computed);

    } else if (crc_type == NRF24_CRC_2BYTE) {
        uint16_t crc_off = (uint16_t)(pld_off + out->payload_len);
        out->crc_received = ((uint16_t)buf[crc_off] << 8) | buf[crc_off + 1];
        out->crc_computed = esb_crc16(buf, crc_data_len);
        out->valid = (out->crc_received == out->crc_computed);

    } else {
        /* Sin CRC — consideramos el frame válido si las longitudes cuadran */
        out->valid = true;
    }

    out->is_ack = (out->payload_len == 0 && !out->no_ack);
    return out->valid;
}

/**
 * esb_parse_promiscuous() — Modo promiscuo: prueba addr_width 3, 4 y 5.
 *
 * Intenta primero CRC-1, luego CRC-2, finalmente sin CRC.
 * Retorna true con el primer parseo válido (CRC OK).
 *
 * @param buf     Buffer crudo (sin preamble)
 * @param buf_len Longitud del buffer
 * @param out     Frame resultado
 * @return true si se encontró un parseo válido con CRC correcto
 */
static inline bool esb_parse_promiscuous(const uint8_t  *buf,
                                          uint16_t        buf_len,
                                          nrf24_frame_t  *out)
{
    static const uint8_t addr_widths[] = {5, 4, 3};
    static const nrf24_crc_t crc_types[] = {NRF24_CRC_1BYTE, NRF24_CRC_2BYTE};

    for (uint8_t ci = 0; ci < 2; ci++) {
        for (uint8_t ai = 0; ai < 3; ai++) {
            if (esb_parse(buf, buf_len, addr_widths[ai], crc_types[ci], out)) {
                return true;
            }
        }
    }
    /* Fallback sin CRC — puede dar falsos positivos */
    return esb_parse(buf, buf_len, 5, NRF24_CRC_NONE, out);
}

/**
 * esb_preamble_for_addr() — Devuelve el preamble correcto para una dirección.
 * Según §7.2 del spec: preamble = 0xAA si MSB del addr[0] == 1, else 0x55.
 */
static inline uint8_t esb_preamble_for_addr(const uint8_t *addr)
{
    return (addr[0] & 0x80U) ? ESB_PREAMBLE_1MBPS : ESB_PREAMBLE_ALT;
}

/* ── Constructor de frames TX ────────────────────────────────────────────────── */

/**
 * esb_build_frame() — Construye un frame ESB listo para transmitir.
 *
 * NO incluye el preamble (el RF core del CC1352P7 lo añade automáticamente
 * según el primer bit del sync word/dirección).
 *
 * Layout del frame de salida:
 *   [ Address (addr_width B) ][ PCF 2B ][ Payload (0-32 B) ][ CRC 0-2B ]
 *
 * PCF (9 bits, empaquetados MSB-first en 2 bytes):
 *   pcf_raw[8:3] = payload_len (6 bits)
 *   pcf_raw[2:1] = pid         (2 bits, 0-3)
 *   pcf_raw[0]   = no_ack      (1 bit)
 *   Byte 0 = pcf_raw >> 1 (bits 8..1)
 *   Byte 1 = (pcf_raw & 1) << 7  (bit 0 en MSB; bits 6..0 son el MSB del payload)
 *
 * @param addr        Dirección destino (MSB primero, 3-5 bytes)
 * @param addr_width  Longitud de la dirección (3, 4 o 5)
 * @param payload     Bytes del payload (puede ser NULL si payload_len == 0)
 * @param payload_len Longitud del payload (0-32)
 * @param pid         Packet ID para deduplicación (0-3)
 * @param no_ack      true → establece el flag NO_ACK
 * @param crc_type    Tipo de CRC a calcular y añadir al final del frame
 * @param out_buf     Buffer de salida — debe tener ≥ ESB_MAX_FRAME_LEN bytes
 * @return  Longitud total del frame (bytes), 0 en caso de parámetros inválidos
 */
static inline uint16_t esb_build_frame(const uint8_t  *addr,
                                        uint8_t         addr_width,
                                        const uint8_t  *payload,
                                        uint8_t         payload_len,
                                        uint8_t         pid,
                                        bool            no_ack,
                                        nrf24_crc_t     crc_type,
                                        uint8_t        *out_buf)
{
    if (!addr || !out_buf) { return 0u; }
    if (addr_width < ESB_ADDR_WIDTH_MIN || addr_width > ESB_ADDR_WIDTH_MAX) { return 0u; }
    if (payload_len > ESB_MAX_PAYLOAD_LEN) { return 0u; }
    if (payload_len > 0u && !payload) { return 0u; }

    uint16_t off = 0u;

    /* 1. Dirección (MSB primero) */
    memcpy(out_buf, addr, addr_width);
    off += addr_width;

    /* 2. PCF — 9 bits empaquetados en 2 bytes */
    uint16_t pcf_raw = ((uint16_t)(payload_len & 0x3Fu) << 3) |
                       ((uint16_t)(pid & 0x03u)          << 1) |
                       (no_ack ? 1u : 0u);
    out_buf[off++] = (uint8_t)(pcf_raw >> 1);           /* bits [8:1] */
    out_buf[off++] = (uint8_t)((pcf_raw & 0x01u) << 7); /* bit  [0] → MSB */

    /* 3. Payload */
    if (payload_len > 0u && payload) {
        memcpy(out_buf + off, payload, payload_len);
        off += payload_len;
    }

    /* 4. CRC — cubre: addr + PCF bytes + payload */
    uint16_t crc_data_len = (uint16_t)(addr_width + 2u + payload_len);

    if (crc_type == NRF24_CRC_1BYTE) {
        out_buf[off++] = esb_crc8(out_buf, crc_data_len);
    } else if (crc_type == NRF24_CRC_2BYTE) {
        uint16_t crc16 = esb_crc16(out_buf, crc_data_len);
        out_buf[off++] = (uint8_t)(crc16 >> 8);
        out_buf[off++] = (uint8_t)(crc16 & 0xFFu);
    }

    return off;
}

/* ── Helpers de formateo (para UART humano) ─────────────────────────────────── */

/**
 * esb_addr_to_hex() — Convierte dirección a string hex "E7E7E7E7E7".
 * @param out_str  Buffer de salida de al menos (addr_width*2 + 1) bytes.
 */
static inline void esb_addr_to_hex(const nrf24_frame_t *f, char *out_str)
{
    static const char hex[] = "0123456789ABCDEF";
    for (uint8_t i = 0; i < f->addr_width; i++) {
        out_str[i * 2]     = hex[f->addr[i] >> 4];
        out_str[i * 2 + 1] = hex[f->addr[i] & 0x0FU];
    }
    out_str[f->addr_width * 2] = '\0';
}

#ifdef __cplusplus
}
#endif

#endif /* NRF24_ESB_H_ */
