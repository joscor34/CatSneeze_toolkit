cmake_minimum_required(VERSION 3.21)

# ── Rutas del SDK TI (ajustar si la instalación es diferente) ────────────────
# Se pueden pasar desde línea de comandos:
#   -DTICC13XX_SDK_PATH="C:/ti/simplelink_cc13xx_cc26xx_sdk_8_32_00_07"
#   -DSYSCONFIG_PATH="C:/ti/sysconfig_1.21.1"
if(NOT DEFINED TICC13XX_SDK_PATH)
    set(TICC13XX_SDK_PATH "C:/ti/simplelink_cc13xx_cc26xx_sdk_8_32_00_07"
        CACHE PATH "Ruta al TI SimpleLink CC13xx/CC26xx SDK")
endif()
if(NOT DEFINED SYSCONFIG_PATH)
    set(SYSCONFIG_PATH "C:/ti/sysconfig_1.21.1"
        CACHE PATH "Ruta al TI SysConfig")
endif()

# ── Configuración del dispositivo ────────────────────────────────────────────
set(DEVICE_FAMILY  "cc13x2x7_cc26x2x7")
set(DEVICE_NAME    "CC1352P7")
set(DEVICE_BOARD   "/ti/boards/LP_CC1352P7_1")
set(DEVICE_DEFINE  "DeviceFamily_CC13X2X7")

# ── Proyecto ─────────────────────────────────────────────────────────────────
project(nrf24_sniffer C ASM)
set(CMAKE_C_STANDARD 99)

# ── Ejecutar SysConfig para generar ti_drivers_config.c / .h ─────────────────
find_program(SYSCONFIG_CMD
    NAMES sysconfig_cli.bat sysconfig_cli sysconfig_cli.sh
    PATHS "${SYSCONFIG_PATH}"
    NO_DEFAULT_PATH
    REQUIRED
)

set(SYSCFG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/nrf24_sniffer.syscfg")
set(SYSCFG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/syscfg")

file(MAKE_DIRECTORY "${SYSCFG_OUTPUT_DIR}")

# Stamp file pattern: evita el bucle "build.ninja still dirty" en Windows.
# SysConfig genera archivos con timestamps nuevos; usar un stamp file permite
# que Ninja controle cuándo re-ejecutar SysConfig sin disparar re-configure.
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
    COMMENT "Generando configuración TI drivers con SysConfig..."
)

add_custom_target(sysconfig_gen DEPENDS "${SYSCONFIG_STAMP}")

set_source_files_properties(
    "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c"
    PROPERTIES GENERATED TRUE
)

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
    "${TICC13XX_SDK_PATH}/source/ti/posix/gcc"
    "${TICC13XX_SDK_PATH}/kernel/nortos"
    "${TICC13XX_SDK_PATH}/kernel/nortos/posix"
)

# ── Defines del dispositivo ───────────────────────────────────────────────────
# CRITICAL: SET_CCFG_BL_CONFIG_* habilitan el BSL backdoor en el CCFG del
# CC1352P7. Sin estos overrides, ccfg.c del SDK compila con
# BL_BACKDOOR_ENABLE=0x00, que deshabilita el BSL por hardware y hace
# imposible re-flashear con catnip/cc2538-bsl sin JTAG.
# El CatSniffer usa DIO13 (pin 0x0D) como pin de trigger, activo en bajo.
# Referencia: TI SDK — source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c
set(DEVICE_DEFINES
    "${DEVICE_DEFINE}"
    # BSL backdoor habilitado → permite re-flashear via RP2040/catnip
    "SET_CCFG_BL_CONFIG_BL_ENABLE=0xC5"
    "SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE=0xC5"
    "SET_CCFG_BL_CONFIG_BL_BACKDOOR_ENABLE=0xC5"
    "SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN=0x0D"
    "SET_CCFG_BL_CONFIG_BL_BACKDOOR_LEVEL=0x0"
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
