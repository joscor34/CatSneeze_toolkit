# arm-none-eabi-toolchain.cmake
# Toolchain file para compilación cruzada ARM Cortex-M4 (CC1352P7)
# Uso:
#   cmake .. -DCMAKE_TOOLCHAIN_FILE=../arm-none-eabi-toolchain.cmake
#
# Requisito: arm-none-eabi-gcc en el PATH.
#   Windows: https://developer.arm.com/downloads/-/gnu-rm
#   macOS:   brew install arm-none-eabi-gcc
#   Linux:   sudo apt install gcc-arm-none-eabi

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# ── Buscar el compilador ──────────────────────────────────────────────────────
find_program(ARM_CC  arm-none-eabi-gcc  REQUIRED)
find_program(ARM_CXX arm-none-eabi-g++ REQUIRED)
find_program(ARM_AS  arm-none-eabi-as  REQUIRED)

set(CMAKE_C_COMPILER   "${ARM_CC}")
set(CMAKE_CXX_COMPILER "${ARM_CXX}")
set(CMAKE_ASM_COMPILER "${ARM_AS}")

# Herramientas binutils
find_program(CMAKE_OBJCOPY arm-none-eabi-objcopy REQUIRED)
find_program(CMAKE_OBJDUMP arm-none-eabi-objdump REQUIRED)
find_program(CMAKE_SIZE    arm-none-eabi-size)

# ── Test de compilador: modo bare-metal (sin OS host) ────────────────────────
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ── No buscar librerías del sistema host ──────────────────────────────────────
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
