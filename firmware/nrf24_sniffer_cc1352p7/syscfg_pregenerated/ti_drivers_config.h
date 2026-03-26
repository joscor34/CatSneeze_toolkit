/*
 *  ======== ti_drivers_config.h ========
 *
 *  Pre-generado por SysConfig para:
 *    Board : LP_CC1352P7-1  (CC1352P7)
 *    SDK   : simplelink_cc13xx_cc26xx_sdk_8_32_00_07
 *    RTOS  : NoRTOS (bare-metal super-loop)
 *    Config: UART2 (XDS110UART, DIO12=RX / DIO13=TX), RF, Power+DC/DC
 *
 *  Propósito: permite compilar y enlazar en CI/CD (GitHub Actions) sin
 *  tener TI SysConfig instalado. Si nrf24_sniffer.syscfg cambia, regenera
 *  con:
 *    sysconfig_cli --product <SDK>/.metadata/product.json \
 *                  --board /ti/boards/LP_CC1352P7_1 \
 *                  --rtos nortos --compiler gcc \
 *                  --output syscfg_pregenerated \
 *                  nrf24_sniffer.syscfg
 *  y reemplaza este directorio con el contenido generado.
 */

#ifndef ti_drivers_config_h
#define ti_drivers_config_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  ======== UART2 ========
 *
 *  CONFIG_UART2_0 → UART0, DIO12 (RX), DIO13 (TX)
 *  Backchannel XDS110 on LP_CC1352P7-1.
 */
#define CONFIG_UART2_0     0
#define CONFIG_UART2_COUNT 1

/*
 *  ======== RF ========
 *  RF_open() gestiona el objeto interno; no se necesita CONFIG_RF_x aquí.
 *  Los comandos RF viven en smartrf_settings.c.
 */

/* DeviceFamily debe definirse antes de los includes del SDK */
#ifndef DeviceFamily_CC13X2X7
#define DeviceFamily_CC13X2X7
#endif

#include <ti/devices/DeviceFamily.h>

/* Inicialización del BSP (llamada al inicio de main()) */
void Board_init(void);
void Board_initGeneral(void);

#ifdef __cplusplus
}
#endif

#endif /* ti_drivers_config_h */
