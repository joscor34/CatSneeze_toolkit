cmake_minimum_required(VERSION 3.21)

# ── Rutas del SDK TI ─────────────────────────────────────────────────────────
# Prioridad de resolución:
#   1. -DTICC13XX_SDK_PATH=<path> en la línea de comandos
#   2. Variable de entorno TICC13XX_SDK_PATH (ideal para CI/GitHub Actions)
#   3. Rutas por defecto según el sistema operativo
#
# Equivalente para SysConfig con SYSCONFIG_PATH / SYSCONFIG_PATH env var.
#
# Opción alternativa para CI sin SysConfig instalado:
#   -DUSE_PREGENERATED_SYSCFG=ON
#   → usa los archivos pre-generados en syscfg_pregenerated/

# SDK
if(NOT DEFINED TICC13XX_SDK_PATH)
    if(DEFINED ENV{TICC13XX_SDK_PATH})
        set(TICC13XX_SDK_PATH "$ENV{TICC13XX_SDK_PATH}"
            CACHE PATH "Ruta al TI SimpleLink CC13xx/CC26xx SDK (desde env)")
    elseif(WIN32)
        set(TICC13XX_SDK_PATH "C:/ti/simplelink_cc13xx_cc26xx_sdk_8_32_00_07"
            CACHE PATH "Ruta al TI SimpleLink CC13xx/CC26xx SDK")
    else()
        set(TICC13XX_SDK_PATH "$ENV{HOME}/ti/simplelink_cc13xx_cc26xx_sdk_8_32_00_07"
            CACHE PATH "Ruta al TI SimpleLink CC13xx/CC26xx SDK")
    endif()
endif()

# SysConfig
if(NOT DEFINED SYSCONFIG_PATH)
    if(DEFINED ENV{SYSCONFIG_PATH})
        set(SYSCONFIG_PATH "$ENV{SYSCONFIG_PATH}"
            CACHE PATH "Ruta al TI SysConfig (desde env)")
    elseif(WIN32)
        set(SYSCONFIG_PATH "C:/ti/sysconfig_1.21.1"
            CACHE PATH "Ruta al TI SysConfig")
    else()
        # En Linux/macOS el SysConfig suele venir dentro del SDK
        set(SYSCONFIG_PATH "${TICC13XX_SDK_PATH}/tools/sysconfig"
            CACHE PATH "Ruta al TI SysConfig")
    endif()
endif()

# ── Opción: archivos SysConfig pre-generados (CI sin SysConfig instalado) ────
option(USE_PREGENERATED_SYSCFG
    "Usar archivos ti_drivers_config.* pre-generados en syscfg_pregenerated/ en lugar de ejecutar SysConfig"
    OFF)

# ── Configuración del dispositivo ────────────────────────────────────────────
set(DEVICE_FAMILY  "cc13x2x7_cc26x2x7")
set(DEVICE_NAME    "CC1352P7")
set(DEVICE_BOARD   "/ti/boards/LP_CC1352P7_1")
set(DEVICE_DEFINE  "DeviceFamily_CC13X2X7")

# ── Proyecto ─────────────────────────────────────────────────────────────────
project(nrf24_sniffer C ASM)
set(CMAKE_C_STANDARD 99)

# ── SysConfig: generar ti_drivers_config.c / .h  ─────────────────────────────
set(SYSCFG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/nrf24_sniffer.syscfg")

if(USE_PREGENERATED_SYSCFG)
    # ── Modo CI: usar archivos pre-generados (no requiere SysConfig instalado) ──
    set(SYSCFG_OUTPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/syscfg_pregenerated")
    if(NOT EXISTS "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c")
        message(FATAL_ERROR
            "USE_PREGENERATED_SYSCFG=ON pero no existe "
            "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c\n"
            "Genera los archivos con SysConfig localmente y vuelve a intentarlo.")
    endif()
    message(STATUS "SysConfig: usando archivos pre-generados en ${SYSCFG_OUTPUT_DIR}")
    # Target dummy para satisfacer add_dependencies(nrf24_sniffer sysconfig_gen)
    add_custom_target(sysconfig_gen)

else()
    # ── Modo normal: ejecutar SysConfig ──────────────────────────────────────
    # Busca sysconfig_cli en Windows (.bat), Linux (.sh) y macOS (.sh)
    find_program(SYSCONFIG_CMD
        NAMES
            sysconfig_cli.bat          # Windows CCS bundled
            sysconfig_cli.sh           # Linux / macOS installer
            sysconfig_cli              # cualquier plataforma (sin extensión)
        PATHS
            "${SYSCONFIG_PATH}"
            "${SYSCONFIG_PATH}/bin"
            "${TICC13XX_SDK_PATH}/tools/sysconfig"
            "${TICC13XX_SDK_PATH}/tools/sysconfig/bin"
        NO_DEFAULT_PATH
    )

    if(NOT SYSCONFIG_CMD)
        message(FATAL_ERROR
            "SysConfig CLI no encontrado.\n"
            "Opciones:\n"
            "  1. Instala TI SysConfig y pasa -DSYSCONFIG_PATH=<ruta>\n"
            "  2. Usa los archivos pre-generados: -DUSE_PREGENERATED_SYSCFG=ON\n"
            "     (requiere que syscfg_pregenerated/ exista en el fuente)")
    endif()

    set(SYSCFG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/syscfg")
    file(MAKE_DIRECTORY "${SYSCFG_OUTPUT_DIR}")

    # Stamp file: evita el bucle "build.ninja still dirty"
    set(SYSCONFIG_STAMP "${SYSCFG_OUTPUT_DIR}/.sysconfig_stamp")

    add_custom_command(
        OUTPUT "${SYSCONFIG_STAMP}"
        COMMAND "${SYSCONFIG_CMD}"
            --product "${TICC13XX_SDK_PATH}/.metadata/product.json"
            --board "${DEVICE_BOARD}"
            --rtos nortos
            --compiler gcc
            --output "${SYSCFG_OUTPUT_DIR}"
            "${SYSCFG_FILE}"
        COMMAND ${CMAKE_COMMAND} -E touch "${SYSCONFIG_STAMP}"
        DEPENDS "${SYSCFG_FILE}"
        BYPRODUCTS
            "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c"
            "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.h"
        COMMENT "Ejecutando SysConfig para generar ti_drivers_config.*..."
    )

    add_custom_target(sysconfig_gen DEPENDS "${SYSCONFIG_STAMP}")

    set_source_files_properties(
        "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c"
        PROPERTIES GENERATED TRUE
    )
endif()

# ── NoRTOS (bare-metal, super-loop) ──────────────────────────────────────────

# ── Fuentes del firmware ──────────────────────────────────────────────────────
# NoRTOS: la librería nortos_cc13x2x7.a proporciona DPL (ClockP, SemaphoreP, etc.)
# Solo compilamos nuestros propios archivos + startup + SysConfig generado
set(SOURCES
    nrf24_sniffer.c
    smartrf_settings.c
    "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}/startup_files/startup_gcc.c"
    "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}/startup_files/ccfg.c"
    "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c"
)

# ── Includes ──────────────────────────────────────────────────────────────────

set(INCLUDES
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${SYSCFG_OUTPUT_DIR}"
    "${TICC13XX_SDK_PATH}/source"
    "${TICC13XX_SDK_PATH}/source/ti"
    "${TICC13XX_SDK_PATH}/source/ti/devices"
    "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}"
    "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}/driverlib"
    "${TICC13XX_SDK_PATH}/source/ti/drivers"
    # Ambos directorios posix del SDK (source/ti/posix/gcc y kernel/nortos/posix)
    # intencionalmente excluidos: su sys/types.h usa '#include <../include/sys/types.h>'
    # con ruta relativa al layout de la toolchain TI, incompatible con
    # libnewlib-arm-none-eabi de Ubuntu. En bare-metal/NoRTOS no usamos POSIX.
    "${TICC13XX_SDK_PATH}/kernel/nortos"
    # kernel/nortos/posix excluido por el mismo motivo que posix/gcc
)

# ── Defines del dispositivo ───────────────────────────────────────────────────
# CRITICAL: SET_CCFG_BL_CONFIG_* habilitan el BSL backdoor en el CCFG del
# CC1352P7. Sin estos overrides, ccfg.c del SDK compila con
# BL_BACKDOOR_ENABLE=0x00, que deshabilita el BSL por hardware y hace
# imposible re-flashear con catnip/cc2538-bsl sin JTAG.
# El CatSniffer V3 usa DIO15 (pin 0x0F) como pin BSL backdoor, activo en bajo.
# El RP2040 (GPIO2=CC1352_BOOT) tira DIO15 a GND antes de RESET para activar BSL.
# Confirmado en simple_central.syscfg oficial CatSniffer V3:
#   CCFG.dioBootloaderBackdoor = 15
# Referencia: TI SDK — source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c
#
# xoscCapArrayDelta: calibración del cristal XOSC_HF para LP_CC1352P7_1.
# Confirmado en lprf_ccfg_settings.js del SDK (xoscCapArrayDelta=0xC1).
set(DEVICE_DEFINES
    "${DEVICE_DEFINE}"
    # BSL backdoor habilitado → permite re-flashear via RP2040/catnip
    "SET_CCFG_BL_CONFIG_BL_ENABLE=0xC5"
    "SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE=0xC5"
    "SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE=0xC5"
    "SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN=0x0F"       # DIO15 — CatSniffer V3
    "SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL=0x0"
    # Calibración del cristal XOSC_HF (LP_CC1352P7_1 / CatSniffer V3)
    "SET_CCFG_MODE_CONF_XOSC_CAP_MOD=0"             # 0 = modificar cap array
    "SET_CCFG_MODE_CONF_XOSC_CAPARRAY_DELTA=0xC1"   # delta LP_CC1352P7_1
)

# ── Librerías del SDK ─────────────────────────────────────────────────────────
set(SDK_LIB_DIR "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}/driverlib/bin/gcc")

# ── Flags del compilador ──────────────────────────────────────────────────────
set(CPU_FLAGS
    -mcpu=cortex-m4
    -mthumb
    -mfloat-abi=hard
    -mfpu=fpv4-sp-d16
)

set(COMMON_FLAGS
    ${CPU_FLAGS}
    -Os
    -ffunction-sections
    -fdata-sections
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# ── Linker script (NoRTOS / bare-metal) ──────────────────────────────────
set(LINKER_SCRIPT
    "${CMAKE_CURRENT_SOURCE_DIR}/cc13x2x7_nortos.lds"
)

# ── Target ────────────────────────────────────────────────────────────────────
add_executable(nrf24_sniffer ${SOURCES})
add_dependencies(nrf24_sniffer sysconfig_gen)

target_include_directories(nrf24_sniffer PRIVATE ${INCLUDES})

target_compile_definitions(nrf24_sniffer PRIVATE ${DEVICE_DEFINES})

target_compile_options(nrf24_sniffer PRIVATE ${COMMON_FLAGS})

target_link_options(nrf24_sniffer PRIVATE
    ${CPU_FLAGS}
    -march=armv7e-m
    -T "${LINKER_SCRIPT}"
    -Wl,--gc-sections
    -Wl,-Map,nrf24_sniffer.map
    -nostartfiles
    -static
    --specs=nano.specs
    --specs=nosys.specs
)

target_link_directories(nrf24_sniffer PRIVATE
    "${TICC13XX_SDK_PATH}/source"
)

target_link_libraries(nrf24_sniffer
    -Wl,--start-group
    "${TICC13XX_SDK_PATH}/source/ti/drivers/rf/lib/gcc/m4f/rf_multiMode_cc13x2.a"
    "${TICC13XX_SDK_PATH}/source/ti/drivers/lib/gcc/m4f/drivers_cc13x2x7.a"
    "${TICC13XX_SDK_PATH}/kernel/nortos/lib/gcc/m4f/nortos_cc13x2x7.a"
    "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}/driverlib/bin/gcc/driverlib.lib"
    -lgcc -lc -lm
    -Wl,--end-group
)

# ── Post-build: generar .bin y .hex para flashear ────────────────────────────
add_custom_command(TARGET nrf24_sniffer POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O ihex
        "$<TARGET_FILE:nrf24_sniffer>"
        "${CMAKE_CURRENT_BINARY_DIR}/nrf24_sniffer.hex"
    COMMAND ${CMAKE_OBJCOPY} -O binary
        "$<TARGET_FILE:nrf24_sniffer>"
        "${CMAKE_CURRENT_BINARY_DIR}/nrf24_sniffer.bin"
    COMMENT "Generando nrf24_sniffer.hex y nrf24_sniffer.bin"
)

message(STATUS "SDK: ${TICC13XX_SDK_PATH}")
message(STATUS "SysConfig: ${SYSCONFIG_PATH}")
message(STATUS "Dispositivo: ${DEVICE_NAME} (${DEVICE_FAMILY})")
