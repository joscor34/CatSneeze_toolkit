/**
 * smartrf_settings.h — Configuración del radio CC1352P7 para nRF24L01+
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  INSTRUCCIONES: Generar con TI SmartRF Studio 7                 │
 * │                                                                  │
 * │  1. Abrir SmartRF Studio 7                                       │
 * │  2. Device: CC1352P7                                             │
 * │  3. Tab "Packet TX/RX" → Protocol: "Custom / Proprietary"       │
 * │  4. Band: 2.4 GHz                                                │
 * │  5. Parámetros según la tabla de abajo                           │
 * │  6. Export → C code                                              │
 * │  7. Reemplazar los bloques TODO_SMARTRF en este archivo          │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Tabla de parámetros SmartRF Studio por tasa:
 *
 *  | Campo              | 250 kbps      | 1 Mbps        | 2 Mbps        |
 *  |--------------------|---------------|---------------|---------------|
 *  | Modulation         | 2-FSK (GFSK)  | 2-FSK (GFSK)  | 2-FSK (GFSK)  |
 *  | Symbol Rate (kBaud)| 250.000       | 1000.000      | 2000.000      |
 *  | Deviation (kHz)    | 160.000       | 160.000       | 500.000       |
 *  | RX Filter BW (kHz) | 600.000       | 1600.000      | 2000.000      |
 *  | Whitening          | Off           | Off           | Off           |
 *  | CRC                | None          | None          | None          |
 *  | Preamble           | 4 bytes 0xAA  | 4 bytes 0xAA  | 4 bytes 0xAA  |
 *  | Sync word          | AAAAAAAA      | AAAAAAAA      | AAAAAAAA      |
 *  | Sync word bits     | 32            | 32            | 32            |
 *  | Packet length      | Fixed 37 B    | Fixed 37 B    | Fixed 37 B    |
 *
 * Nota sobre la banda 2.4 GHz en CC1352P7:
 *   El CC1352P7 usa el motor de radio propietario con loDivider=5 para
 *   acceder a la banda 2.400–2.525 GHz. centerFreq configura el canal:
 *   centerFreq (MHz) = 2400 + RF_CH
 *   Canal default nRF24: 76 → centerFreq = 2476
 */
#ifndef SMARTRF_SETTINGS_H_
#define SMARTRF_SETTINGS_H_

#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/rf_prop_cmd.h>
#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/rf_mailbox.h>

/* ── Overrides para banda 2.4 GHz propietaria en CC1352P7 ───────────────────
 *
 * Estos overrides activan el front-end de 2.4 GHz del CC1352P7.
 * SmartRF Studio los incluye en el array pRegOverride exportado.
 * Sustituir TODO_SMARTRF_OVERRIDES con el contenido exportado.
 *
 * Ejemplo típico de override para 2.4 GHz prop GFSK (de proyectos conocidos):
 */
#define TODO_SMARTRF_OVERRIDES  /* ← pegue aquí el array de overrides SmartRF */

/* Overrides de referencia para 2.4 GHz propietario CC1352P7 (aproximados):
 * Validar siempre con SmartRF Studio antes de usar en producción. */
static uint32_t pOverrides_nrf24_1M[] = {
    /* 2.4 GHz front-end enable */
    0x00158000,   /* HW_REG_OVERRIDE(0x5320,0x0015) */
    0x05300243,   /* HW_REG_OVERRIDE(0x0486,0x5300) — GFSK shape */
    0xFFFFFFFF,   /* end marker */
};

/* ── CMD_PROP_RADIO_DIV_SETUP  ——  1 Mbps GFSK, canal 76 (2476 MHz) ─────────
 *
 * Valores marcados TODO_SMARTRF_* deben ser reemplazados con la salida
 * exacta de SmartRF Studio 7 para CC1352P7 a 1 Mbps GFSK.
 *
 * Valores de referencia documentados (verificar con SmartRF Studio):
 *   symbolRate.preScale   = 0xF  (divide-by-16 prescaler)
 *   symbolRate.rateWord   = 0x200000  (aprox. 1 Mbps con preScale=15)
 *   modulation.deviation  = 0x280  (160000 Hz / 250 Hz por unidad = 640 = 0x280)
 *   rxBw                  = 0x59  (≈ 1600 kHz de BW)
 *   centerFreq            = 2476  (canal 76, 2476 MHz)
 *   intFreq               = 0x0999  (IF = 2.4375 MHz)
 *   loDivider             = 0x05  (÷5 para 2.4 GHz)
 *
 * IMPORTANTE: dejamos las estructuras `.modulation` y `.symbolRate` con
 * los valores de referencia pero MARCADAS para reemplazo con SmartRF Studio.
 */
rfc_CMD_PROP_RADIO_DIV_SETUP_t RF_nrf24_cmdPropRadioDivSetup_1M = {
    .commandNo                  = 0x3807,   /* CMD_PROP_RADIO_DIV_SETUP */
    .status                     = 0x0000,
    .pNextOp                    = 0,
    .startTime                  = 0x00000000,
    .startTrigger.triggerType   = 0x0,      /* TRIG_NOW */
    .startTrigger.bEnaCmd       = 0x0,
    .startTrigger.triggerNo     = 0x0,
    .startTrigger.pastTrig      = 0x0,
    .condition.rule             = 0x1,      /* COND_ALWAYS */
    .condition.nSkip            = 0x0,

    /* ── Modulación: 2-GFSK ──────────────────────────────────────────────── */
    .modulation.modType         = 0x1,      /* 2-FSK (GFSK con shape en overrides) */
    /* TODO_SMARTRF: reemplazar con valor SmartRF. Ref: 160 kHz dev = 0x280 */
    .modulation.deviation       = 0x280,    /* 160.000 kHz (unidades 250 Hz) */
    .modulation.deviationStepSz = 0x0,

    /* ── Symbol rate: 1 Mbps ─────────────────────────────────────────────── */
    /* TODO_SMARTRF: reemplazar con valores SmartRF exactos para 1 Mbps */
    .symbolRate.preScale        = 0xF,      /* preScale=15 */
    .symbolRate.rateWord        = 0x200000, /* ≈ 1 Mbps con preScale=15, HF=48MHz */
    .symbolRate.decimMode       = 0x0,

    /* ── RX bandwidth ────────────────────────────────────────────────────── */
    /* TODO_SMARTRF: reemplazar con valor SmartRF. Ref: 1600 kHz = 0x59 */
    .rxBw                       = 0x59,

    /* ── Preamble / Sync ─────────────────────────────────────────────────── */
    .preamConf.nPreamBytes      = 0x4,      /* 4 bytes de preamble (0xAA×4) */
    .preamConf.preamMode        = 0x0,
    .formatConf.nSwBits         = 32,       /* sync word = 32 bits = 4 bytes */
    .formatConf.bBitReversal    = 0x0,
    .formatConf.bMsbFirst       = 0x1,      /* MSB primero — igual que nRF24 */
    .formatConf.bDualSw         = 0x0,
    .formatConf.fecMode         = 0x0,

    /* ── Front-end ───────────────────────────────────────────────────────── */
    .config.frontEndMode        = 0x0,      /* Diferencial */
    .config.biasMode            = 0x1,      /* bias interno */
    .config.analogCfgMode       = 0x0,
    .config.bNoFsPowerUp        = 0x0,

    /* TODO_SMARTRF: TX power adecuada para 2.4 GHz */
    .txPower                    = 0xCCC0,   /* ~0 dBm */
    .pRegOverride               = pOverrides_nrf24_1M,

    /* ── Frecuencia ──────────────────────────────────────────────────────── */
    .centerFreq                 = 2476,     /* Canal 76 = 2476 MHz (default nRF24) */
    .intFreq                    = 0x0999,   /* IF = 2.4375 MHz */
    .loDivider                  = 0x05,     /* ÷5 para 2.4 GHz */
};

/**
 * RF_nrf24_update_channel() — Cambia el canal del setup command en RAM.
 * Llamar ANTES de CMD_PROP_RADIO_DIV_SETUP si se cambia de canal.
 *
 * @param channel  Canal nRF24 (0–125). Frecuencia = 2400 + channel MHz.
 */
static inline void RF_nrf24_update_channel(uint8_t channel)
{
    if (channel > 125) { channel = 125; }
    RF_nrf24_cmdPropRadioDivSetup_1M.centerFreq = (uint16_t)(2400u + channel);
}

/* ── CMD_PROP_RX_ADV — configuración del receptor promiscuo ─────────────────
 *
 * Modo promiscuo:
 *   - syncWord = 0xAAAAAAAA  (preamble trick para capturar cualquier nRF24)
 *   - Sin filtro de dirección HW
 *   - Longitud fija = 37 bytes (max ESB posible)
 *   - Sin CRC HW (parseamos en software)
 */
rfc_CMD_PROP_RX_ADV_t RF_nrf24_cmdPropRxAdv = {
    .commandNo              = 0x3804,   /* CMD_PROP_RX_ADV */
    .status                 = 0x0000,
    .pNextOp                = 0,
    .startTime              = 0x00000000,
    .startTrigger.triggerType = 0x0,    /* TRIG_NOW */
    .condition.rule         = 0x1,      /* COND_ALWAYS */

    /* ── Paquete ─────────────────────────────────────────────────────────── */
    .pktConf.bFsOff         = 0x0,
    .pktConf.bRepeatOk      = 0x1,      /* continuar en bucle tras RX OK */
    .pktConf.bRepeatNok     = 0x1,      /* continuar en bucle tras RX NOK */
    .pktConf.bUseCrc        = 0x0,      /* sin CRC hardware */
    .pktConf.bCrcIncSw      = 0x0,
    .pktConf.endType        = 0x0,
    .pktConf.endConf        = 0x0,
    .pktConf.bIncludeCrc    = 0x1,      /* incluir bytes CRC en el buffer */
    .pktConf.fltStop        = 0x1,

    /* ── Longitud fija = 37 bytes ────────────────────────────────────────── */
    .maxPktLen              = 37,
    .hdrConf.numHdrBits     = 0x0,      /* sin header */
    .hdrConf.lenPos         = 0,
    .hdrConf.numLenBits     = 0,

    /* ── Sync word = 0xAAAAAAAA (preamble trick) ─────────────────────────── */
    .syncWord0              = 0xAAAAAAAAUL,
    .syncWord1              = 0x00000000UL,
    .syncWordLen            = 32,       /* 4 bytes */
    .maxSyncWordLen         = 32,
    .syncThresh             = 0,

    /* Buffer y dirección del output se configuran en nrf24_sniffer.c */
    .pOutput                = 0,
    .addrConf.addrType      = 0x0,      /* sin filtro de dirección HW */
    .addrConf.addrSize      = 0x0,
    .addrConf.addrPos       = 0x0,
    .addrConf.numAddr       = 0x0,

    /* RX timeout = forever */
    .endTime                = 0x00000000,
    .endTrigger.triggerType = 0x1,      /* TRIG_NEVER (bloqueante hasta dato) */
};

/* ── CMD_PROP_TX — transmisión ESB ─────────────────────────────────────────
 *
 * Configuración base para TX propietario en 2.4 GHz (1 Mbps GFSK).
 * Se usa para:
 *   - Inyección MouseJack (spoofing de dispositivos nRF24L01+ sin cifrado)
 *   - Replay de frames capturados
 *
 * Antes de ejecutar CMD_PROP_TX:
 *   1. RF_nrf24_cmdPropTx.pPkt    = puntero al frame ESB ya construido
 *   2. RF_nrf24_cmdPropTx.pktLen  = longitud del frame
 *   3. Aplicar RF_nrf24_update_channel(ch) para ajustar el canal
 *
 * NOTA IMPORTANTE: El CC1352P7 añade automáticamente el preamble (0xAA/0x55)
 * según el MSB del syncWord, por lo que el frame pasado en pPkt NO debe
 * incluir el preamble — empieza directamente con los bytes de Address.
 */
rfc_CMD_PROP_TX_t RF_nrf24_cmdPropTx = {
    .commandNo                  = 0x3801,   /* CMD_PROP_TX */
    .status                     = 0x0000,
    .pNextOp                    = 0,
    .startTime                  = 0x00000000,
    .startTrigger.triggerType   = 0x0,      /* TRIG_NOW */
    .startTrigger.bEnaCmd       = 0x0,
    .startTrigger.triggerNo     = 0x0,
    .startTrigger.pastTrig      = 0x0,
    .condition.rule             = 0x1,      /* COND_ALWAYS */

    .pktConf.bFsOff             = 0x0,      /* mantener sintetizador activo */
    .pktConf.bUseCrc            = 0x0,      /* sin CRC HW (ya incluido en pPkt) */
    .pktConf.bVarLen            = 0x0,      /* longitud fija especificada en pktLen */

    /* syncWord = dirección del target con preamble correcto.
     * Se actualiza en rf_tx_frame() según la addr del frame a enviar. */
    .syncWord                   = 0xAAAAAAAAUL,

    .pktLen                     = 0,        /* se actualiza antes de cada TX */
    .pPkt                       = 0,        /* se actualiza antes de cada TX */
};

#endif /* SMARTRF_SETTINGS_H_ */
