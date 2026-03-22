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

add_custom_command(
    OUTPUT
        "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.c"
        "${SYSCFG_OUTPUT_DIR}/ti_drivers_config.h"
    COMMAND "${SYSCONFIG_CMD}"
        --product "${TICC13XX_SDK_PATH}/.metadata/product.json"
        --device "${DEVICE_NAME}"
        --output "${SYSCFG_OUTPUT_DIR}"
        "${SYSCFG_FILE}"
    DEPENDS "${SYSCFG_FILE}"
    COMMENT "Generando configuración TI drivers con SysConfig..."
)

# ── Fuentes del firmware ──────────────────────────────────────────────────────
set(SOURCES
    nrf24_sniffer.c
    smartrf_settings.c
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
    "${TICC13XX_SDK_PATH}/kernel/tirtos7/packages"
    "${TICC13XX_SDK_PATH}/kernel/tirtos7/packages/ti/sysbios/knl"
)

# ── Defines del dispositivo ───────────────────────────────────────────────────
set(DEVICE_DEFINES
    "${DEVICE_DEFINE}"
    "TIRTOS7_Support"
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

# ── Linker script ─────────────────────────────────────────────────────────────
set(LINKER_SCRIPT
    "${TICC13XX_SDK_PATH}/source/ti/devices/${DEVICE_FAMILY}/linker_files/cc13x2x7.lds"
)

# ── Target ────────────────────────────────────────────────────────────────────
add_executable(nrf24_sniffer ${SOURCES})

target_include_directories(nrf24_sniffer PRIVATE ${INCLUDES})

target_compile_definitions(nrf24_sniffer PRIVATE ${DEVICE_DEFINES})

target_compile_options(nrf24_sniffer PRIVATE ${COMMON_FLAGS})

target_link_options(nrf24_sniffer PRIVATE
    ${CPU_FLAGS}
    -T "${LINKER_SCRIPT}"
    -Wl,--gc-sections
    -Wl,-Map="${CMAKE_CURRENT_BINARY_DIR}/nrf24_sniffer.map"
    -nostartfiles
)

target_link_libraries(nrf24_sniffer
    "${SDK_LIB_DIR}/driverlib.lib"
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
