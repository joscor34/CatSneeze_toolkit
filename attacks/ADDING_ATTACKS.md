# How to add a new attack

1. Create a file in the right category folder (or make a new one):

   ```
   attacks/
   └── ble/
       └── my_new_attack.py
   ```

2. Write the class:

   ```python
   from attacks.base import BaseAttack, AttackOption
   from attacks.registry import AttackRegistry

   @AttackRegistry.register
   class MyAttack(BaseAttack):
       name           = "my_attack"
       description    = "One-line description shown in the menu"
       firmware_alias = "sniffle"      # catnip firmware alias to auto-flash
       category       = "BLE"         # shown as menu category

       options = [
           AttackOption("channel", "BLE channel (37-39)", default=37, type=int),
       ]

       def run(self, device) -> None:
           ch = self.get_option("channel")
           # device.bridge_port  → main serial port (CC1352 data)
           # device.shell_port   → config / shell serial port
           # device.lora_port    → SX1262 LoRa port
           ...
   ```

3. That's it — the menu auto-discovers it on startup.

## New category

Create `attacks/<category>/` with an `__init__.py` that mirrors the BLE one.
