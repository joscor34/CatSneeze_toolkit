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
└── attacks/
    ├── base.py           # BaseAttack ABC  + AttackOption dataclass
    ├── registry.py       # Global attack registry (decorator-based)
    ├── ADDING_ATTACKS.md # Guide to add new attacks
    └── ble/
        └── airtag_spoofer.py
```

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
