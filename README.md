# CatSniffer Toolkit

Modular CLI toolkit for the [CatSniffer v3](https://electroniccats.com) IoT research hardware.

```
   /\_____/\
  /  o   o  \    CatSniffer Toolkit
 ( ==  ^  == )
  )         (
 (           )
( (  )   (  ) )
(__(__)___(__)__)
```

## Requirements

- Python 3.10+
- [catnip](https://github.com/ElectronicCats/CatSniffer-Tools) installed and on `PATH` (or set `CATNIP_PATH`)
- CatSniffer v3 hardware

```bash
pip install -r requirements.txt
```

## Quick start

```bash
# Interactive menu (recommended)
python main.py

# List all available attacks
python main.py list

# List connected devices
python main.py devices

# Run an attack directly (non-interactive)
python main.py run airtag_spoofer
python main.py run airtag_spoofer --set flash=no --set baud=9600
```

## Menu navigation

```
Main Menu
  [1] BLE  (2 attacks)
  [d] Devices — rescan / select
  [q] Quit

Category: BLE
  [1] airtag_spoofer   Broadcast fake Apple AirTag / FindMy BLE advertisements
  [2] ...

Attack: airtag_spoofer
  [r] run attack
  [o] options
  [b] back
```

## Attacks available

```
[BLE] airtag_scanner       Detecta AirTags / FindMy BLE en el entorno
[BLE] airtag_spoofer       Emite anuncios BLE falsos de AirTag / FindMy
[BLE] ble_sniffer          Sniffer BLE pasivo (Sniffle firmware)
[BLE] justworks_scanner    Detecta dispositivos BLE JustWorks (sin PIN)

[RF]  nrf24_sniffer        nRF24L01+ ESB sniffer (promiscuo, dirigido, scan)
[RF]  nrf24_spoofer        nRF24L01+ ESB spoofer / MouseJack keystroke inject
[RF]  nrf24_replayer       nRF24L01+ capture + replay interactivo
[RF]  zigbee_sniffer       Zigbee / IEEE 802.15.4 sniffer
```

## Architecture

```
CatSniffer_my_tool/
├── main.py               # Entry point — click CLI + menu launcher
├── shell.py              # Rich interactive menu
├── config.py             # Global constants
├── requirements.txt
│
├── core/
│   ├── device.py         # CatSniffer USB detection (pyserial)
│   ├── firmware.py       # Firmware flashing (catnip subprocess)
│   └── ui.py             # Shared Rich helpers
│
├── attacks/
│   ├── base.py           # BaseAttack ABC  + AttackOption dataclass
│   ├── registry.py       # Global attack registry (decorator-based)
│   ├── ADDING_ATTACKS.md # Guide to add new attacks
│   ├── ble/
│   │   ├── airtag_scanner.py
│   │   ├── airtag_spoofer.py
│   │   ├── ble_sniffer.py
│   │   └── justworks_scanner.py
│   └── rf/
│       ├── zigbee_sniffer.py
│       ├── nrf24_sniffer.py   # RX pasivo + PCAP export
│       ├── nrf24_spoofer.py   # TX: MouseJack keystroke / string / raw
│       └── nrf24_replayer.py  # Captura + REPLAY:RAW_HEX interactivo
│
└── firmware/
    └── nrf24_sniffer_cc1352p7/
        ├── README.md          # Instrucciones completas de build + uso
        ├── nrf24_sniffer.c    # Firmware principal (RX + TX)
        ├── nrf24_esb.h        # Parser + builder ESB portable
        └── smartrf_settings.h # Config radio CC1352P7 (RX + TX)
```

## nRF24L01+ / ESB attacks (nuevo)

El firmware `nrf24-sniffer` añade soporte nRF24L01+ Enhanced ShockBurst
sobre el CC1352P7 del CatSniffer — el **primer firmware nRF24/ESB para este
hardware** (no existe en el ecosistema oficial de Electronic Cats).

**Flujo típico de auditoría:**
```bash
# 1. Sniff promiscuo — descubrir dispositivos y addresses
python main.py run nrf24_sniffer --set channel=scan --set mode=scan

# 2. Sniff dirigido — capturar tráfico del target
python main.py run nrf24_sniffer \
  --set mode=directed --set addr=E7E7E7E7E7 --set channel=76 --set export_pcap=s

# 3a. MouseJack — inyectar comando (dispositivo HID vulnerable)
python main.py run nrf24_spoofer \
  --set target_addr=E7E7E7E7E7 --set mode=string \
  --set string=calc --set shell_exec=s

# 3b. Replay — retransmitir un frame capturado
python main.py run nrf24_replayer \
  --set mode=directed --set addr=E7E7E7E7E7 --set channel=76
```

Ver [firmware/nrf24_sniffer_cc1352p7/README.md](firmware/nrf24_sniffer_cc1352p7/README.md) para instrucciones completas de compilación, protocolo UART y vectores de ataque.

## Adding a new attack

See [attacks/ADDING_ATTACKS.md](attacks/ADDING_ATTACKS.md) — it's 3 steps.

## catnip setup

The toolkit relies on `catnip` for firmware flashing.  Clone and install it:

```bash
git clone https://github.com/ElectronicCats/CatSniffer-Tools.git
cd CatSniffer-Tools/catnip
pip install .
# Verify
catnip --help
```

Or point the toolkit to a local script:

```bash
export CATNIP_PATH="$HOME/CatSniffer-Tools/catnip/catnip.py"
python main.py
```

## Disclaimer

This toolkit is for **authorized security research and educational use only**.
Always obtain explicit permission before testing on networks or devices you do not own.
