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
 * Pin BSL del CatSniffer: DIO13 (0x0D), activo en nivel bajo.
 * El RP2040 tira este pin a GND antes de hacer RESET al CC1352P7 para
 * activar el bootloader serial (BSL) en lugar del firmware principal.
 *
 * Referencia: TI SDK — source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c
 *
 * Overrides activos (definidos en CMakeLists.txt):
 *   SET_CCFG_BL_CONFIG_BL_ENABLE            = 0xC5   BSL habilitado
 *   SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE    = 0xC5   bootloader habilitado
 *   SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE   = 0xC5   backdoor por pin habilitado
 *   SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN      = 0x0D   pin DIO13
 *   SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL    = 0x0    activo en bajo
 */
#ifndef CCFG_APP_H
#define CCFG_APP_H

/*
 * Guardas de seguridad: si ccfg.c incluye este header directamente,
 * los defines están aquí también como fallback.
 */
#ifndef SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE
#define SET_CCFG_BL_CONFIG_BL_ENABLE            0xC5
#define SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE    0xC5
#define SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE   0xC5
#define SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN      0x0D
#define SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL    0x0
#endif

#endif /* CCFG_APP_H */
