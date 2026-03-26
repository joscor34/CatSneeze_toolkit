/*
 *  ======== ti_drivers_config.c ========
 *
 *  Pre-generado por SysConfig para:
 *    Board : LP_CC1352P7-1  (CC1352P7)
 *    SDK   : simplelink_cc13xx_cc26xx_sdk_8_32_00_07
 *    RTOS  : NoRTOS (bare-metal super-loop)
 *    Config: UART2 (XDS110UART, DIO12=RX / DIO13=TX), RF, Power+DC/DC
 *
 *  Ver ti_drivers_config.h para instrucciones de regeneración con SysConfig.
 *
 *  NOTA DE PINES (LP_CC1352P7-1 backchannel UART):
 *    UART0_RX → DIO12 (IOID_12)
 *    UART0_TX → DIO13 (IOID_13)
 *  Si usas otra tarjeta (p.ej. CatSniffer v3 custom board), ajusta rxPin/txPin.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Debe definirse ANTES de incluir cualquier header del SDK */
#ifndef DeviceFamily_CC13X2X7
#define DeviceFamily_CC13X2X7
#endif

#include <ti/devices/DeviceFamily.h>
#include "ti_drivers_config.h"

/* DeviceFamily_constructPath() mapea al directorio correcto del dispositivo.
 * Para CC13X2X7 expande a:
 *   source/ti/devices/cc13x2x7_cc26x2x7/<arg>
 */
#include DeviceFamily_constructPath(inc/hw_memmap.h)
#include DeviceFamily_constructPath(inc/hw_ints.h)
#include DeviceFamily_constructPath(driverlib/ioc.h)
#include DeviceFamily_constructPath(driverlib/udma.h)

/* ═══════════════════════════════════════════════════════════════════════════
 *  Power — PowerCC26X2 con DC/DC habilitado (perfil LP_CC1352P7-1)
 * ═══════════════════════════════════════════════════════════════════════════ */
#include <ti/drivers/Power.h>
#include <ti/drivers/power/PowerCC26X2.h>

const PowerCC26X2_Config PowerCC26X2_config = {
    .policyInitFxn      = NULL,
    .policyFxn          = &PowerCC26XX_standbyPolicy,
    .calibrateFxn       = &PowerCC26XX_calibrate,
    .enablePolicy       = true,
    .calibrateRCOSC_LF  = true,
    .calibrateRCOSC_HF  = true,
    .vddrRechargeMargin = 0,
    .enableTCXOFxn      = NULL,
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  RF — Atributos hardware del driver RF para CC26X2/CC13X2 (NoRTOS)
 *
 *  RFCC26XX_hwAttrs debe estar definido globalmente; el driver RF lo accede
 *  en RF_open(). Sin esta tabla el linker emite "undefined reference to
 *  RFCC26XX_hwAttrs".
 *
 *  Las antenas switch (DIO28/DIO29/DIO30 = RFC_GPO0/1/2) se configuran
 *  mediante IOCPortConfigureSet() en nrf24_sniffer.c antes de RF_open(),
 *  por lo que no necesitamos el campo de pin automation aquí.
 * ═══════════════════════════════════════════════════════════════════════════ */
#include <ti/drivers/rf/RF.h>
/* RFCC26XX_HWAttrsV2 está expuesto por RF.h para dispositivos CC13X2X7/CC26X2X7. */

const RFCC26XX_HWAttrsV2 RFCC26XX_hwAttrs = {
    .hwiPriority        = (~0),   /* menor prioridad HWI */
    .swiPriority        = 0,
    .xoscHfAlwaysNeeded = true,   /* XOSC_HF activo mientras RF está abierto */
    .globalEventMask    = 0,
    .globalCallback     = NULL,
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  µDMA — requerido por el driver UART2CC26X2 para TX/RX DMA
 * ═══════════════════════════════════════════════════════════════════════════ */
#include <ti/drivers/dma/UDMACC26XX.h>

/*
 *  Tabla de control µDMA: 64 entradas × 16 bytes = 1024 bytes.
 *  Debe estar alineada a 1024 bytes (requisito hardware).
 *  UDMACC26XX_init() escribe su dirección en el registro UDMA0_BASE + CTRL,
 *  por lo que el linker solo necesita que esté en SRAM (no en dirección fija).
 *
 *  Asignación de canales µDMA para CC1352P7 (ver TRM §UDMA Channel Assignments):
 *    Canal 1 → UART0 RX  (DMA_UART0_RX_CONTROL_TABLE_ENTRY_ADDRESS = BASE+0x10)
 *    Canal 2 → UART0 TX  (DMA_UART0_TX_CONTROL_TABLE_ENTRY_ADDRESS = BASE+0x20)
 */
static tDMAControlTable dmaControlTable[64]
    __attribute__((aligned(1024)));

UDMACC26XX_Object udmaCC26XXObjects[1];

const UDMACC26XX_HWAttrs udmaCC26XXHWAttrs = {
    .baseAddr      = UDMA0_BASE,
    .powerMngrId   = PowerCC26XX_PERIPH_UDMA,
    .intNum        = INT_DMA_ERR,
    .intPriority   = (~0),
    .pControlTable = dmaControlTable,
};

const UDMACC26XX_Config UDMACC26XX_config[1] = {
    {
        .object  = &udmaCC26XXObjects[0],
        .hwAttrs = &udmaCC26XXHWAttrs,
    },
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  UART2 — UART0 periférico, backchannel XDS110 de LP_CC1352P7-1
 *           DIO12 = RX (IOID_12),  DIO13 = TX (IOID_13)
 *           Baud configurable en run-time (nrf24_sniffer.c usa 921600).
 * ═══════════════════════════════════════════════════════════════════════════ */
#include <ti/drivers/UART2.h>
#include <ti/drivers/uart2/UART2CC26X2.h>

UART2CC26X2_Object uart2CC26X2Objects[CONFIG_UART2_COUNT];

/* Buffer ring para RX asíncrono (callback mode en NoRTOS) */
static unsigned char uart2RxBuf0[32];

/*
 *  NOTA sobre rxPin / txPin:
 *  En SDK 8.x, estos campos son uint_least8_t y reciben el número de DIO
 *  (0–30).  IOID_12 = 0x0C = 12, IOID_13 = 0x0D = 13.
 *  Se hace cast explícito para evitar warning por truncación implícita.
 *
 *  ctsPin / rtsPin = 0xFF → IOID_UNUSED (no conectados, flujo none).
 */
const UART2CC26X2_HWAttrs uart2CC26X2HWAttrs[CONFIG_UART2_COUNT] = {
    {   /* CONFIG_UART2_0 */
        .baseAddr      = UART0_BASE,
        .intNum        = INT_UART0_COMB,
        .intPriority   = (~0),
        .swiPriority   = 0,
        .flowControl   = UART2_FLOWCTRL_NONE,
        .rxBufPtr      = uart2RxBuf0,
        .rxBufSize     = sizeof(uart2RxBuf0),
        .txBufPtr      = NULL,
        .txBufSize     = 0,
        .rxPin         = (uint_least8_t)(IOID_12 & 0xFFu),   /* DIO12 = 12 */
        .txPin         = (uint_least8_t)(IOID_13 & 0xFFu),   /* DIO13 = 13 */
        .ctsPin        = (uint_least8_t)(IOID_UNUSED & 0xFFu),
        .rtsPin        = (uint_least8_t)(IOID_UNUSED & 0xFFu),
        .txDmaEntry    = &dmaControlTable[UDMA_CHAN_UART0_TX],
        .rxDmaEntry    = &dmaControlTable[UDMA_CHAN_UART0_RX],
        .rxChannelMask = (1u << UDMA_CHAN_UART0_RX),
        .txChannelMask = (1u << UDMA_CHAN_UART0_TX),
        .powerId       = PowerCC26XX_PERIPH_UART0,
    },
};

const UART2_Config UART2_config[CONFIG_UART2_COUNT] = {
    {   /* CONFIG_UART2_0 */
        .object  = &uart2CC26X2Objects[CONFIG_UART2_0],
        .hwAttrs = &uart2CC26X2HWAttrs[CONFIG_UART2_0],
    },
};

const uint_least8_t UART2_count = CONFIG_UART2_COUNT;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Board_init — Inicialización del BSP
 * ═══════════════════════════════════════════════════════════════════════════ */
void Board_init(void)
{
    /* 1. Sistema de gestión de energía (debe ser siempre lo primero) */
    Power_init();

    /* 2. Controlador µDMA (necesario para UART2 con DMA) */
    UDMACC26XX_init(&UDMACC26XX_config[0]);
}

void Board_initGeneral(void)
{
    Board_init();
}
