/**
 * ccfg_app.h — Documentación de los overrides CCFG para nrf24_sniffer (CC1352P7)
 *
 * Los valores reales se pasan via -D flags en CMakeLists.txt (método estándar TI).
 * Este archivo documenta los defines y sirve de referencia.
 *
 * CRITICAL: SIN los SET_CCFG_BL_CONFIG_* defines, ccfg.c del SDK compila con
 * BL_BACKDOOR_ENABLE=0x00, que deshabilita el BSL por hardware e impide
 * re-flashear el chip con catnip/cc2538-bsl sin JTAG.
 *
 * Pin BSL del CatSniffer V3: DIO15 (0x0F), activo en nivel bajo.
 * El RP2040 (GPIO2=CC1352_BOOT) tira DIO15 a GND antes de hacer RESET al CC1352P7
 * para activar el bootloader serial (BSL) en lugar del firmware principal.
 * Confirmado en simple_central.syscfg del firmware oficial CatSniffer V3:
 *   CCFG.dioBootloaderBackdoor = 15
 *
 * Referencia: TI SDK — source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c
 *
 * Overrides activos (definidos en CMakeLists.txt):
 *   SET_CCFG_BL_CONFIG_BL_ENABLE            = 0xC5   BSL habilitado
 *   SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE    = 0xC5   bootloader habilitado
 *   SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE   = 0xC5   backdoor por pin habilitado
 *   SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN      = 0x0F   pin DIO15 (CatSniffer V3)
 *   SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL    = 0x0    activo en bajo
 *   SET_CCFG_MODE_CONF_XOSC_CAP_MOD         = 0      modificar cap array XOSC
 *   SET_CCFG_MODE_CONF_XOSC_CAPARRAY_DELTA  = 0xC1   delta cristal LP_CC1352P7_1
 */
#ifndef CCFG_APP_H
#define CCFG_APP_H

/*
 * Guardas de seguridad: si ccfg.c incluye este header directamente,
 * los defines están aquí también como fallback.
 *
 * CRITICAL: El SDK 8.32 usa BL_PIN_NUMBER y BL_LEVEL (no BL_BACKDOOR_*).
 * Se definen ambas convenciones para cubrir todas las versiones del SDK.
 */

/* Nombres SDK 8.32 (ccfg.c real) */
#ifndef SET_CCFG_BL_CONFIG_BL_PIN_NUMBER
#define SET_CCFG_BL_CONFIG_BL_PIN_NUMBER        0x0F   /* DIO15 — CatSniffer V3 */
#endif
#ifndef SET_CCFG_BL_CONFIG_BL_LEVEL
#define SET_CCFG_BL_CONFIG_BL_LEVEL             0x0    /* activo en bajo */
#endif
#ifndef SET_CCFG_BL_CONFIG_BL_ENABLE
#define SET_CCFG_BL_CONFIG_BL_ENABLE            0xC5
#endif
#ifndef SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE
#define SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE    0xC5
#endif

/* Nombres alternativos (documentación CatSniffer / otros SDKs) */
#ifndef SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE
#define SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE   0xC5
#endif
#ifndef SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN
#define SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN      0x0F   /* DIO15 — CatSniffer V3 */
#endif
#ifndef SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL
#define SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL    0x0
#endif

#ifndef SET_CCFG_MODE_CONF_XOSC_CAP_MOD
#define SET_CCFG_MODE_CONF_XOSC_CAP_MOD        0
#define SET_CCFG_MODE_CONF_XOSC_CAPARRAY_DELTA 0xC1    /* LP_CC1352P7_1 */
#endif

#endif /* CCFG_APP_H */
