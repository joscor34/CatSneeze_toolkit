# Guía de Recuperación y Estado del Proyecto CatSniffer

> Documento generado: 22 marzo 2026  
> Aplica a: **CatSniffer v3** (RP2040 + CC1352P7)

---

## Contexto

El CC1352P7 quedó "brickeado" por un CCFG con `BL_BACKDOOR_PIN=0xFF` (pin no conectado),
lo que impedía que catnip abriera el BSL de forma automática. Se recuperó vía JTAG
usando el RP2040 como programador cJTAG + OpenOCD.

---

## Estado actual del hardware (tras la sesión de recuperación)

| Chip | Estado |
|---|---|
| CC1352P7 | Firmware `nrf24_sniffer.hex` escrito vía JTAG ✓ |
| RP2040 | Ejecutando `free_dap_catsniffer.uf2` (modo JTAG) — necesita restaurarse |

---

## Paso 1 — Terminar sesión OpenOCD (si aún está abierta)

En la sesión telnet (puerto 4444):
```
> reset
> exit
```

Luego en la terminal donde corre OpenOCD: **Ctrl+C**

---

## Paso 2 — Restaurar RP2040 a modo serial passthrough

El RP2040 debe volver al firmware `SerialPassthroughwithboot_RP2040_v1.1.uf2`
para que catnip pueda comunicarse con el CC1352P7.

### 2.1 — Entrar en DFU del RP2040 (secuencia CatSniffer v3)

> ⚠️ Esta secuencia es **distinta** del método estándar (hold BOOT + plug USB).
> En CatSniffer v3, el cable USB debe estar **ya conectado** y luego:

```
1. Presionar RESET1
2. (sin soltar RESET1) Presionar SW1
3. Soltar RESET1
4. Soltar SW1
```

El volumen `RPI-RP2` debería aparecer en el Finder.

### 2.2 — Copiar el firmware

```bash
cp /ruta/a/SerialPassthroughwithboot_RP2040_v1.1.uf2 /Volumes/RPI-RP2/
```

O arrastrar el `.uf2` al volumen `RPI-RP2` en el Finder.

El RP2040 rebootea automáticamente. Deberían aparecer 3 puertos serie:
```bash
ls /dev/cu.usbmodem*
```

---

## Paso 3 — Verificar que el CC1352P7 arranca

Con el RP2040 en serial passthrough, abrir el puerto serie del CC1352P7:

```bash
screen /dev/cu.usbmodem<PUERTO> 115200
```

Salida esperada al arrancar:
```
===== nRF24L01+ Sniffer (CC1352P7) =====
[INIT] ch=076 freq=2476MHz rate=1M mode=PROMISC
```

Si aparece eso, el firmware funciona correctamente.

> Para salir de `screen`: **Ctrl+A** → **K** → **Y**

---

## Paso 4 — Recompilar con el fix de CCFG (Windows)

El firmware que hay en el chip ahora tiene `BL_BACKDOOR_PIN=0xFF` (el hex viejo).
El `CMakeLists.txt` ya tiene el fix (`BL_BACKDOOR_PIN=0x0D`), pero hay que
recompilar para generar un nuevo `.hex` y que catnip vuelva a funcionar sin
pulsar botones manualmente.

### 4.1 — Compilar (PowerShell en Windows)

```powershell
cd firmware\nrf24_sniffer_cc1352p7

# Limpiar build anterior
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Name build | Out-Null
cd build

# Configurar
cmake .. -G "Ninja" `
  -DCMAKE_TOOLCHAIN_FILE="../arm-none-eabi-toolchain.cmake" `
  -DTICC13XX_SDK_PATH="C:/ti/simplelink_cc13xx_cc26xx_sdk_8_32_00_07" `
  -DSYSCONFIG_PATH="C:/ti/sysconfig_1.21.1"

# Compilar
cmake --build . --target nrf24_sniffer 2>&1
```

El nuevo hex se guarda en `build/nrf24_sniffer.hex`.  
Copiar al directorio de compiled firmware:
```powershell
Copy-Item build\nrf24_sniffer.hex ..\compiled_firmware\nrf24_sniffer.hex
```

### 4.2 — Flashear con catnip (ya sin pulsar botones)

Una vez que `BL_BACKDOOR_PIN=0x0D` esté en el chip, catnip podrá
abrir el BSL automáticamente:
```bash
catnip flash firmware/nrf24_sniffer_cc1352p7/compiled_firmware/nrf24_sniffer.hex
```

---

## Paso 5 — (Opcional) Re-añadir el comando BSL por UART

Una vez que el firmware compile y funcione, se puede añadir el comando
`BSL\r\n` para reiniciar el CC1352P7 en modo BSL desde Python sin pulsar botones.

En `nrf24_sniffer.c`, añadir los includes:
```c
#include <ti/devices/cc13x2x7/driverlib/sys_ctrl.h>
#include <ti/devices/cc13x2x7/inc/hw_aon_pmctl.h>
```

Y el handler del comando:
```c
} else if (strncmp(cmd_buf, "BSL", 3) == 0) {
    // Resetear al BSL: escribir 0x2 en AON_PMCTL y luego system reset
    HWREG(AON_PMCTL_BASE + AON_PMCTL_O_RESETCTL) = 0x2;
    SysCtrlSystemReset();
}
```

---

## Procedimiento de recuperación JTAG (referencia para próximas veces)

Documentado aquí porque puede que sea necesario repetirlo si vuelve a haber
un CCFG malo.

### Requisitos

- OpenOCD ≥ 0.12.0 instalado (`brew install open-ocd`)
- `free_dap_catsniffer.uf2` para el RP2040
- `SerialPassthroughwithboot_RP2040_v1.1.uf2` para restaurar el RP2040

### Fix del TAPID en OpenOCD (CC1352P7 específico)

El CC1352P7 usa TAPID `0x1bb7702f` pero el script de TI espera `0x0bb4102f`.
Parchear una sola vez tras instalar OpenOCD:

```bash
sed -i '' \
  's/set JRC_TAPID 0x0BB4102F/set JRC_TAPID 0x1bb7702f/g' \
  /opt/homebrew/Cellar/open-ocd/0.12.0_1/share/openocd/scripts/target/ti_cc13x2.cfg
```

Verificar:
```bash
grep JRC_TAPID /opt/homebrew/Cellar/open-ocd/0.12.0_1/share/openocd/scripts/target/ti_cc13x2.cfg
# → set JRC_TAPID 0x1bb7702f  ✓
```

### Secuencia completa de recuperación

**Terminal 1 — Arrancar OpenOCD:**
```bash
openocd \
  -f /opt/homebrew/Cellar/open-ocd/0.12.0_1/share/openocd/scripts/interface/cmsis-dap.cfg \
  -f /opt/homebrew/Cellar/open-ocd/0.12.0_1/share/openocd/scripts/target/ti_cc13x2.cfg
```
Esperar a ver: `Listening on port 3333 for gdb connections`

**Terminal 2 — Conectar por telnet:**
```bash
telnet localhost 4444
```

**Comandos en telnet:**
```
halt            # detener el núcleo
reset halt      # si hay HardFault, esto suele resolver
flash erase_sector 0 1 last   # borrar sectores 1-87 (sector 0 puede estar protegido)
flash write_image erase /ruta/absoluta/compiled_firmware/nrf24_sniffer.hex
reset
exit
```

> **Nota:** Si `flash erase_sector 0 0 last` falla ("Cannot erase protected sector"),
> saltar al sector 1. El write_image rellena el gap correctamente.

**Cerrar OpenOCD:**
```
Ctrl+C en Terminal 1
```

---

## Checklist de estado del proyecto

- [x] Bug DataQueue corregido (`g_rxEntry`/`g_rxQueue` en `rx_one_packet()`)
- [x] `bRepeatOk = 0x0` en `smartrf_settings.c`
- [x] `SET_CCFG_BL_CONFIG_BL_BACKDOOR_PIN=0x0D` en `CMakeLists.txt`
- [x] `ccfg_app.h` creado con los overrides CCFG
- [x] CC1352P7 reflasheado vía JTAG (firmware body correcto)
- [x] TAPID de OpenOCD parcheado para CC1352P7
- [ ] RP2040 restaurado con `SerialPassthroughwithboot_RP2040_v1.1.uf2`
- [ ] Verificar salida UART del CC1352P7 (`[INIT] ch=076...`)
- [ ] Recompilar firmware con CCFG fix (Windows + TI SDK)
- [ ] Flashear nuevo hex con catnip (test auto-BSL)
- [ ] Añadir comando BSL por UART a `nrf24_sniffer.c`
