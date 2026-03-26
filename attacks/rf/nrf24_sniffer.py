"""
RF — nRF24L01+ Enhanced ShockBurst Sniffer
═══════════════════════════════════════════
Requiere el firmware personalizado `nrf24-sniffer` (CC1352P7).
Ver firmware/nrf24_sniffer_cc1352p7/README.md para compilar y flashear.

Protocolo nRF24L01+ Enhanced ShockBurst (ESB)
──────────────────────────────────────────────
Protocolo propietario de Nordic Semiconductor. Opera a 2.4 GHz ISM, con
GFSK (BT=0.5), tasas de 250 kbps / 1 Mbps / 2 Mbps, en canales:
  frecuencia = 2400 + RF_CH [MHz],  RF_CH ∈ [0, 125]

Formato de frame:
  [ Preamble 1B ][ Address 3-5B ][ PCF 9bits ][ Payload 0-32B ][ CRC 1-2B ]

PCF (Packet Control Field):
  bits[8:3] → Payload Length (0-32)
  bits[2:1] → PID (Packet ID, deduplicación)
  bit[0]    → NO_ACK flag

Modo promiscuo (sin conocer la dirección):
  Se usa sync_word = 0xAAAAAAAA para capturar cualquier frame nRF24.
  Técnica de Travis Goodspeed (2011) / MouseJack (Bastille, 2016).

Ataques posibles
────────────────
  • Passive sniff      — decodifica tráfico entre dos dispositivos
  • Channel scan       — mapea dispositivos nRF24 activos en rango
  • MouseJack          — inyección de keystrokes HID (ver --mode mousejack)
  • Address discovery  — descubre dirección del target en modo promiscuo
  • Replay attack      — exige hardware TX (otro CC1352 o nRF24)
"""
from __future__ import annotations

import json
import re
import select
import subprocess
import threading
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

import serial
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()

# ── Expresiones regulares para el protocolo UART del firmware ──────────────────

_PKT_RE  = re.compile(
    r"\[PKT\]\s+ch=(\d+)\s+rssi=([+-]?\d+)\s+len=(\d+)\s+raw=([0-9A-Fa-f]+)"
)
_ESB_RE  = re.compile(
    r"\[ESB\]\s+ch=(\d+)\s+rssi=([+-]?\d+)\s+addr=([0-9A-Fa-f]+)"
    r"\s+plen=(\d+)\s+pid=(\d+)\s+noack=(\d+)\s+pld=([0-9A-Fa-f]*)\s+crc=(\w+)"
)
_ACK_RE  = re.compile(
    r"\[ACK\]\s+ch=(\d+)\s+rssi=([+-]?\d+)\s+addr=([0-9A-Fa-f]+)\s+empty"
)
_SCAN_RE = re.compile(
    r"\[SCAN\]\s+ch=(\d+)\s+active=(\d+)\s+pkts=(\d+)\s+rssi_max=([+-]?\d+)"
)
_INIT_RE = re.compile(
    r"\[INIT\]\s+ch=(\d+)\s+freq=(\d+)MHz\s+rate=(\w+)\s+mode=(\w+)"
)
_CMD_RE  = re.compile(r"\[CMD\]\s+(.*)")
_ERR_RE  = re.compile(r"\[ERR\]\s+(.*)")

# ── Canal → frecuencia ────────────────────────────────────────────────────────
def _ch_freq(ch: int) -> int:
    return 2400 + ch


# ── HID Keystroke Decoder (MouseJack / Boot Protocol) ───────────────────────
# Referencia: USB HID Usage Tables v1.12 §10 Keyboard/Keypad Page (0x07)

_HID_USAGE_MAP: dict[int, tuple[str, str]] = {
    # keycode: (normal, shifted)
    0x04: ("a","A"), 0x05: ("b","B"), 0x06: ("c","C"), 0x07: ("d","D"),
    0x08: ("e","E"), 0x09: ("f","F"), 0x0A: ("g","G"), 0x0B: ("h","H"),
    0x0C: ("i","I"), 0x0D: ("j","J"), 0x0E: ("k","K"), 0x0F: ("l","L"),
    0x10: ("m","M"), 0x11: ("n","N"), 0x12: ("o","O"), 0x13: ("p","P"),
    0x14: ("q","Q"), 0x15: ("r","R"), 0x16: ("s","S"), 0x17: ("t","T"),
    0x18: ("u","U"), 0x19: ("v","V"), 0x1A: ("w","W"), 0x1B: ("x","X"),
    0x1C: ("y","Y"), 0x1D: ("z","Z"),
    0x1E: ("1","!"), 0x1F: ("2","@"), 0x20: ("3","#"), 0x21: ("4","$"),
    0x22: ("5","%"), 0x23: ("6","^"), 0x24: ("7","&"), 0x25: ("8","*"),
    0x26: ("9","("), 0x27: ("0",")"),
    0x28: ("[Enter]","[Enter]"), 0x29: ("[Esc]","[Esc]"),
    0x2A: ("[Bksp]","[Bksp]"),  0x2B: ("\t","\t"),
    0x2C: (" "," "),
    0x2D: ("-","_"),  0x2E: ("=","+"),
    0x2F: ("[","{"),  0x30: ("]","}"),  0x31: ("\\","|"),
    0x33: (";",":"),  0x34: ("'","\""), 0x35: ("`","~"),
    0x36: (",","<"),  0x37: (".",">"),(0x38): ("/","?"),
    0x3A: ("[F1]","[F1]"),  0x3B: ("[F2]","[F2]"),
    0x3C: ("[F3]","[F3]"),  0x3D: ("[F4]","[F4]"),
    0x3E: ("[F5]","[F5]"),  0x3F: ("[F6]","[F6]"),
    0x40: ("[F7]","[F7]"),  0x41: ("[F8]","[F8]"),
    0x42: ("[F9]","[F9]"),  0x43: ("[F10]","[F10]"),
    0x44: ("[F11]","[F11]"), 0x45: ("[F12]","[F12]"),
    0x49: ("[Ins]","[Ins]"),  0x4A: ("[Home]","[Home]"),
    0x4B: ("[PgUp]","[PgUp]"), 0x4C: ("[Del]","[Del]"),
    0x4D: ("[End]","[End]"),  0x4E: ("[PgDn]","[PgDn]"),
    0x4F: ("[→]","[→]"),  0x50: ("[←]","[←]"),
    0x51: ("[↓]","[↓]"),  0x52: ("[↑]","[↑]"),
}

_HID_MOD_SHIFT = 0x02 | 0x20   # LShift | RShift


def decode_hid_payload(payload_hex: str) -> str | None:
    """
    Decodifica un payload HID Boot Protocol de 8 bytes (MouseJack / Unifying).
    Boot Protocol: [modifier 1B][reserved 1B][keycode × 6]
    Modifier bitmask: 0x01=LCtrl 0x02=LShift 0x04=LAlt 0x08=LGui
                      0x10=RCtrl 0x20=RShift 0x40=RAlt 0x80=RGui
    Retorna los caracteres decodificados, o None si el payload no es HID válido.
    """
    try:
        b = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if len(b) != 8:
        return None
    modifier = b[0]
    shift    = bool(modifier & _HID_MOD_SHIFT)
    parts: list[str] = []
    for kc in b[2:8]:
        if kc == 0:
            continue
        entry = _HID_USAGE_MAP.get(kc)
        if entry:
            parts.append(entry[1] if shift else entry[0])
        else:
            parts.append(f"<{kc:#04x}>")
    return "".join(parts) if parts else None


# ── Flash vía catnip ─────────────────────────────────────────────────────────

def _send_bsl_command(port: str) -> bool:
    """
    Envía el comando BSL\r\n al firmware nrf24_sniffer corriendo en el CC1352P7.
    El firmware ejecuta SysCtrlSystemReset() con el flag BSL → el chip arranca
    en modo bootloader serial sin necesidad de pulsar botones físicos.
    Funciona SOLO si el firmware nrf24_sniffer ya está cargado y corriendo.
    """
    import serial as _serial, time as _time
    try:
        with _serial.Serial(port, 921600, timeout=1) as s:
            _time.sleep(0.1)
            s.write(b"BSL\r\n")
            _time.sleep(0.8)   # esperar a que el CC1352P7 rebootee a BSL
        return True
    except Exception as e:
        console.print(f"[yellow]BSL cmd fallido ({e}) — catnip lo intentará vía hardware[/yellow]")
        return False


def flash_hex_direct(hex_path: str, port: str) -> bool:
    """
    Flashea un .hex al CC1352P7 usando `catnip flash <hex_path>`.
    Primero intenta entrar en BSL vía comando UART (si el firmware ya está
    corriendo); si falla, catnip lo intentará vía reset hardware (DTR/RTS).
    """
    if not Path(hex_path).exists():
        console.print(f"[red]Archivo no encontrado:[/red] {hex_path}")
        return False
    console.print("[dim]Enviando comando BSL al firmware…[/dim]")
    _send_bsl_command(port)
    cmd = ["catnip", "flash", hex_path]
    console.print(f"[dim]→ {' '.join(cmd)}[/dim]")
    try:
        proc = subprocess.run(
            cmd, timeout=120,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
        )
        output = proc.stdout or ""
        # Mostrar la salida de catnip en tiempo real (ya buffereada)
        for line in output.splitlines():
            console.print(f"[dim]{line}[/dim]")
        # catnip puede retornar 0 aunque falle — detectamos por texto
        _error_markers = ("Error flashing", "Error:", "[X]", "Timeout waiting")
        failed = proc.returncode != 0 or any(m in output for m in _error_markers)
        return not failed
    except FileNotFoundError:
        console.print("[red]catnip no encontrado en PATH.[/red]")
        return False
    except subprocess.TimeoutExpired:
        console.print("[red]Timeout al flashear (>120s)[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Error al flashear: {e}[/red]")
        return False


# ── Modelo de datos ────────────────────────────────────────────────────────────

class _DeviceRecord:
    """Dispositivo nRF24 detectado por address."""

    def __init__(self, addr: str):
        self.addr        = addr
        self.pkts        = 0
        self.acks        = 0
        self.rssi_max    = -120
        self.rssi_last   = -120
        self.channels    : set[int] = set()
        self.payloads    : list[str] = []   # últimos 5 payloads hex
        self.pid_history : list[int] = []   # PIDs recientes (detección replay)
        self.first_seen  = datetime.now().strftime("%H:%M:%S")
        self.last_seen   = datetime.now().strftime("%H:%M:%S")
        self.no_ack_count = 0
        self.keystrokes  : list[str] = []   # caracteres HID decodificados

    def decoded_string(self) -> str:
        """Reconstruye el string tecleado a partir de los keystrokes HID capturados."""
        return "".join(self.keystrokes)

    def update(self, ch: int, rssi: int, payload_hex: str = "",
               ack: bool = False, no_ack: bool = False, pid: int = -1,
               hid_char: str | None = None):
        now = datetime.now().strftime("%H:%M:%S")
        self.last_seen  = now
        self.rssi_last  = rssi
        if rssi > self.rssi_max:
            self.rssi_max = rssi
        self.channels.add(ch)
        if ack:
            self.acks += 1
        else:
            self.pkts += 1
            if payload_hex:
                self.payloads.append(payload_hex)
                if len(self.payloads) > 5:
                    self.payloads.pop(0)
            if no_ack:
                self.no_ack_count += 1
        if pid >= 0:
            self.pid_history.append(pid)
            if len(self.pid_history) > 32:
                self.pid_history.pop(0)
        if hid_char is not None:
            self.keystrokes.append(hid_char)


class _ScanResult:
    """Resultado de un canal en modo SCAN."""

    def __init__(self, ch: int):
        self.ch       = ch
        self.active   = False
        self.pkts     = 0
        self.rssi_max = -120


# ── Módulo Python nRF24 ESB (replicar lógica del header C) ───────────────────

CRC8_POLY = 0x07
CRC16_POLY = 0x1021


def _crc8(data: bytes) -> int:
    crc = 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc << 1) ^ CRC8_POLY if (crc & 0x80) else crc << 1
            crc &= 0xFF
    return crc


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ CRC16_POLY if (crc & 0x8000) else crc << 1
            crc &= 0xFFFF
    return crc


def decode_esb_frame(raw: bytes, addr_width: int = 5) -> dict | None:
    """
    Decodifica un frame ESB crudo (sin preamble).
    Útil para verificación en Python de frames capturados.

    raw        : bytes del frame, empezando en el byte de dirección
    addr_width : 3, 4 o 5 (intentar los tres si se desconoce)
    """
    min_len = addr_width + 2  # addr + PCF
    if len(raw) < min_len:
        return None

    addr = raw[:addr_width]
    pcf_raw = ((raw[addr_width] << 1) | (raw[addr_width + 1] >> 7)) & 0x1FF
    plen    = (pcf_raw >> 3) & 0x3F
    pid     = (pcf_raw >> 1) & 0x03
    no_ack  = pcf_raw & 0x01

    if plen > 32:
        return None

    pld_start = addr_width + 2
    pld_end   = pld_start + plen

    if len(raw) < pld_end + 1:
        return None

    payload  = raw[pld_start:pld_end]
    crc_data = raw[:pld_end]

    # Probar CRC-8
    if len(raw) >= pld_end + 1:
        crc_rx8 = raw[pld_end]
        crc_ok8 = (_crc8(crc_data) == crc_rx8)
    else:
        crc_rx8 = None
        crc_ok8 = False

    # Probar CRC-16
    if len(raw) >= pld_end + 2:
        crc_rx16 = (raw[pld_end] << 8) | raw[pld_end + 1]
        crc_ok16 = (_crc16(crc_data) == crc_rx16)
    else:
        crc_rx16 = None
        crc_ok16 = False

    return {
        "addr"    : addr.hex().upper(),
        "plen"    : plen,
        "pid"     : pid,
        "no_ack"  : bool(no_ack),
        "payload" : payload.hex().upper(),
        "crc8_ok" : crc_ok8,
        "crc16_ok": crc_ok16,
        "valid"   : crc_ok8 or crc_ok16,
    }


# ── Ataque ─────────────────────────────────────────────────────────────────────

@AttackRegistry.register
class NRF24Sniffer(BaseAttack):
    # ── Metadata ──────────────────────────────────────────────────────────────
    name        = "nrf24_sniffer"
    description = "Audit nRF24L01+ Enhanced ShockBurst (promiscuous or targeted)"
    firmware_alias = "nrf24-sniffer"   # alias a añadir en catnip/CatSniffer-Tools
    category    = "RF"

    options = [
        AttackOption(
            name="flash",
            description="Flash firmware antes de ejecutar (yes/no)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
        AttackOption(
            name="channel",
            description="Canal nRF24 (0-125, o 'scan' para escaneo automático)",
            default="76",
            type=str,
        ),
        AttackOption(
            name="mode",
            description="promisc = sin conocer addr | directed = con addr conocida | scan = escanear canales",
            default="promisc",
            type=str,
            choices=["promisc", "directed", "scan"],
        ),
        AttackOption(
            name="addr",
            description="Dirección nRF24 objetivo en hex (e.g. E7E7E7E7E7) — sólo modo directed",
            default="E7E7E7E7E7",
            type=str,
        ),
        AttackOption(
            name="rate",
            description="Tasa inalámbrica del target",
            default="1M",
            type=str,
            choices=["1M", "2M", "250K"],
        ),
        AttackOption(
            name="baud",
            description="Baud rate UART del firmware",
            default="921600",
            type=str,
            choices=["9600", "115200", "500000", "921600"],
        ),
        AttackOption(
            name="export_pcap",
            description="Guardar paquetes en archivo PCAP (ruta, o vacío para no guardar)",
            default="",
            type=str,
        ),
        AttackOption(
            name="export_json",
            description="Exportar frames a JSON Lines (ruta .jsonl, vacío = no guardar)",
            default="",
            type=str,
        ),
        AttackOption(
            name="filter_addr",
            description="Capturar solo de esta dirección hex (vacío = todas)",
            default="",
            type=str,
        ),
        AttackOption(
            name="hex_path",
            description="Ruta al .hex para flash directo sin catnip (vacío = usar catnip)",
            default="",
            type=str,
        ),
        AttackOption(
            name="decode_hid",
            description="Decodificar payloads HID automáticamente (MouseJack keystroke recovery)",
            default="yes",
            type=str,
            choices=["yes", "no"],
        ),
    ]

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self, device) -> None:
        if self.get_option("flash") == "yes":
            hex_path = self.get_option("hex_path").strip()

            # Ubicaciones donde puede estar el .hex compilado (en orden de preferencia)
            _compiled_candidates = [
                Path(hex_path) if hex_path else None,
                Path(__file__).parents[2]
                    / "firmware" / "nrf24_sniffer_cc1352p7"
                    / "compiled_firmware" / "nrf24_sniffer.hex",
                Path(__file__).parents[2]
                    / "firmware" / "nrf24_sniffer_cc1352p7"
                    / "_build" / "nrf24_sniffer.hex",
            ]
            resolved_hex = next(
                (str(p) for p in _compiled_candidates if p and p.exists()), None
            )

            if resolved_hex is None:
                UI.error(
                    "No se encontró el firmware personalizado nrf24_sniffer.hex.\n"
                    "  Este ataque requiere un firmware custom — catnip flashea el\n"
                    "  firmware stock de CatSniffer, que no entiende el protocolo ESB.\n\n"
                    "  Opciones:\n"
                    "  • [bold]Opción A[/bold] — Descarga el .hex desde GitHub Actions:\n"
                    "      repo → Actions → último run verde → Artifacts\n"
                    "      → nrf24-sniffer-cc1352p7-<sha>.zip\n"
                    "      Luego: [bold]hex_path=<ruta>/nrf24_sniffer.hex[/bold]\n\n"
                    "  • [bold]Opción B[/bold] — Compila localmente (requiere TI SDK):\n"
                    "      firmware/nrf24_sniffer_cc1352p7/README.md\n\n"
                    "  • [bold]Opción C[/bold] — Usa [bold]flash=no[/bold] si el firmware\n"
                    "      ya está en el dispositivo."
                )
                return

            UI.info(f"Flashing [bold]{resolved_hex}[/bold] → {device.bridge_port}…")
            if not flash_hex_direct(resolved_hex, device.bridge_port):
                UI.error("Flash fallido. Comprueba el puerto y que el .hex sea válido.")
                return
            UI.success("Firmware flasheado correctamente.")
            time.sleep(2)

        mode        = self.get_option("mode")
        channel     = self.get_option("channel").strip()
        rate        = self.get_option("rate")
        addr        = self.get_option("addr").upper().strip()
        baud        = int(self.get_option("baud"))
        pcap        = self.get_option("export_pcap").strip()
        json_path   = self.get_option("export_json").strip()
        filter_addr = self.get_option("filter_addr").upper().strip()
        do_hid      = self.get_option("decode_hid") == "yes"

        port = device.bridge_port

        # Validaciones básicas
        if mode == "directed" and len(addr) not in (6, 8, 10):  # 3,4,5 bytes hex
            UI.error(f"Dirección [{addr}] inválida. Usa 6, 8 o 10 chars hex (e.g. E7E7E7E7E7).")
            return

        if channel.lower() == "scan":
            mode = "scan"
            initial_cmd = "CH:SCAN"
        elif mode == "scan":
            initial_cmd = "CH:SCAN"
        elif mode == "directed":
            initial_cmd = f"ADDR:{addr}"
        else:
            try:
                ch_int = int(channel)
                if not 0 <= ch_int <= 125:
                    raise ValueError
            except ValueError:
                UI.error("Canal inválido. Usa 0-125 o 'scan'.")
                return
            initial_cmd = f"CH:{int(channel):03d}"

        self._run_sniffer(
            device, port, baud, initial_cmd, rate, mode, addr, pcap,
            filter_addr=filter_addr, json_path=json_path, decode_hid=do_hid,
        )

    # ── Sniffer loop ───────────────────────────────────────────────────────────

    def _run_sniffer(self, device, port, baud: int,
                     initial_cmd: str, rate: str, mode: str,
                     addr: str, pcap_path: str,
                     filter_addr: str = "",
                     json_path: str = "",
                     decode_hid: bool = True) -> None:

        devices_by_addr : "OrderedDict[str, _DeviceRecord]" = OrderedDict()
        scan_results    : dict[int, _ScanResult] = {}
        event_log       : list[str] = []
        raw_log         : list[str] = []
        lock            = threading.Lock()
        start           = time.time()
        _running        = [True]

        pcap_fh = None
        if pcap_path:
            try:
                pcap_fh = _PCAPWriter(pcap_path)
                UI.info(f"PCAP exportando a: [bold]{pcap_path}[/bold]")
            except OSError as e:
                UI.warning(f"No se pudo abrir PCAP: {e}")

        json_fh = None
        if json_path:
            try:
                json_fh = _JSONWriter(json_path)
                UI.info(f"JSON exportando a: [bold]{json_path}[/bold]")
            except OSError as e:
                UI.warning(f"No se pudo abrir JSON: {e}")

        def _log_event(msg: str):
            with lock:
                ts = datetime.now().strftime("%H:%M:%S")
                event_log.append(f"[{ts}] {msg}")
                if len(event_log) > 20:
                    event_log.pop(0)

        def _reader():
            try:
                with serial.Serial(port, baud, timeout=1) as ser:
                    # Enviar comando inicial
                    time.sleep(0.3)
                    ser.write(f"{initial_cmd}\r\n".encode())
                    ser.write(f"RATE:{rate}\r\n".encode())

                    while _running[0]:
                        raw = ser.readline()
                        if not raw:
                            continue
                        try:
                            line = raw.decode("utf-8", errors="replace").strip()
                        except Exception:
                            continue
                        if not line:
                            continue

                        with lock:
                            raw_log.append(line)
                            if len(raw_log) > 15:
                                raw_log.pop(0)

                        _parse_line(line)

            except serial.SerialException as e:
                _log_event(f"[red]Serial error: {e}[/red]")

        def _parse_line(line: str):
            # [ESB] — frame decodificado
            m = _ESB_RE.search(line)
            if m:
                ch    = int(m.group(1))
                rssi  = int(m.group(2))
                a     = m.group(3).upper()
                plen  = int(m.group(4))
                pid   = int(m.group(5))
                noack = m.group(6) == "1"
                pld   = m.group(7).upper()
                crc   = m.group(8)
                # Filtro por dirección
                if filter_addr and a != filter_addr:
                    return
                # Decodificación HID (MouseJack keystroke recovery)
                hid_char = decode_hid_payload(pld) if (decode_hid and pld) else None
                with lock:
                    if a not in devices_by_addr:
                        devices_by_addr[a] = _DeviceRecord(a)
                    devices_by_addr[a].update(
                        ch, rssi, pld, no_ack=noack, pid=pid, hid_char=hid_char
                    )
                if pcap_fh:
                    try:
                        pcap_fh.write_frame(bytes.fromhex(pld) if pld else b"",
                                             rssi, ch)
                    except Exception:
                        pass
                if json_fh:
                    try:
                        json_fh.write_frame(
                            a, ch, rssi, plen, pid, noack, pld,
                            crc_ok=(crc == "OK"), hid_decoded=hid_char,
                        )
                    except Exception:
                        pass
                hid_info = (
                    f" [yellow]HID:[/yellow][bold]{hid_char}[/bold]"
                    if hid_char else ""
                )
                _log_event(
                    f"[cyan]{a}[/cyan] ch={ch} plen={plen} pid={pid} "
                    f"crc=[{'green' if crc == 'OK' else 'red'}]{crc}"
                    f"[/{'green' if crc == 'OK' else 'red'}]{hid_info}"
                )
                return

            # [ACK] — acknowledge vacío
            m = _ACK_RE.search(line)
            if m:
                ch   = int(m.group(1))
                rssi = int(m.group(2))
                a    = m.group(3).upper()
                if filter_addr and a != filter_addr:
                    return
                with lock:
                    if a not in devices_by_addr:
                        devices_by_addr[a] = _DeviceRecord(a)
                    devices_by_addr[a].update(ch, rssi, ack=True)
                _log_event(f"[dim cyan]{a}[/dim cyan] ch={ch} [dim]ACK[/dim]")
                return

            # [SCAN] — resultado de escaneo de canal
            m = _SCAN_RE.search(line)
            if m:
                ch       = int(m.group(1))
                active   = m.group(2) == "1"
                pkts     = int(m.group(3))
                rssi_max = int(m.group(4))
                with lock:
                    if ch not in scan_results:
                        scan_results[ch] = _ScanResult(ch)
                    scan_results[ch].active   = active
                    scan_results[ch].pkts     = pkts
                    scan_results[ch].rssi_max = rssi_max
                return

            # [ERR] / [CMD]
            m = _ERR_RE.search(line) or _CMD_RE.search(line)
            if m:
                _log_event(line)

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        def _build_panel(elapsed: float) -> Panel:
            mins, secs = divmod(int(elapsed), 60)
            with lock:
                snap_devs  = list(devices_by_addr.values())
                snap_scan  = dict(scan_results)
                snap_evlog = list(event_log[-15:])
                snap_raw   = list(raw_log[-10:])

            # ── Header ──
            hdr = Table(box=None, show_header=False, padding=(0, 2))
            hdr.add_column(style="dim cyan", no_wrap=True)
            hdr.add_column(style="white")
            hdr.add_row("Port", str(port))
            hdr.add_row("Firmware", self.firmware_alias)
            hdr.add_row("Mode", f"[bold]{mode.upper()}[/bold]")
            hdr.add_row("Rate", rate)
            hdr.add_row("Uptime", f"[bold green]{mins:02d}:{secs:02d}[/bold green]")
            hdr.add_row("Devices", f"[bold yellow]{len(snap_devs)}[/bold yellow]")

            # ── Tabla de dispositivos detectados ──
            any_hid  = any(rec.keystrokes for rec in snap_devs)
            col_names = ["Address", "Ch(s)", "Pkts", "ACKs", "RSSI now",
                         "RSSI max", "Last payload", "First", "Last"]
            if any_hid:
                col_names.append("Keystrokes (HID)")
            dev_tbl = Table(
                *col_names,
                box=None, show_header=True,
                header_style="bold dim",
                padding=(0, 1),
            )
            for rec in snap_devs:
                chs = ",".join(str(c) for c in sorted(rec.channels)[:5])
                pld_preview = (rec.payloads[-1][:20] + "…") if rec.payloads else "[dim]—[/dim]"
                row = [
                    f"[bold cyan]{rec.addr}[/bold cyan]",
                    chs or "?",
                    str(rec.pkts),
                    str(rec.acks),
                    f"{rec.rssi_last} dBm",
                    f"{rec.rssi_max} dBm",
                    pld_preview,
                    rec.first_seen,
                    rec.last_seen,
                ]
                if any_hid:
                    ks = rec.decoded_string()
                    if ks:
                        preview = ks[:28] + "…" if len(ks) > 28 else ks
                        row.append(f"[bold yellow]{preview}[/bold yellow]")
                    else:
                        row.append("[dim]—[/dim]")
                dev_tbl.add_row(*row)

            # ── Tabla de SCAN (sólo en modo scan) ──
            scan_part = None
            if mode == "scan" and snap_scan:
                active_chs = [r for r in snap_scan.values() if r.active]
                scan_tbl = Table(
                    "Ch", "Freq(MHz)", "Pkts", "RSSI max",
                    box=None, show_header=True,
                    header_style="bold dim", padding=(0, 1),
                )
                for r in sorted(active_chs, key=lambda x: -x.pkts):
                    scan_tbl.add_row(
                        f"[bold]{r.ch:03d}[/bold]",
                        str(_ch_freq(r.ch)),
                        str(r.pkts),
                        f"{r.rssi_max} dBm",
                    )
                scan_part = scan_tbl

            # ── Event log ──
            evlog_text = "\n".join(snap_evlog) if snap_evlog else "[dim](esperando tráfico…)[/dim]"

            body = Table(box=None, show_header=False, padding=(0, 0))
            body.add_column()
            body.add_row(hdr)
            body.add_row(Rule(style="dim"))
            body.add_row(Text(f"📡 Dispositivos nRF24 detectados — {len(snap_devs)}", style="bold"))
            body.add_row(dev_tbl if snap_devs else "[dim](no hay tramas aún)[/dim]")

            if scan_part:
                body.add_row(Rule(style="dim"))
                active_count = sum(1 for r in snap_scan.values() if r.active)
                body.add_row(Text(f"🔍 Canales activos: {active_count} / {len(snap_scan)}", style="bold"))
                body.add_row(scan_part)

            body.add_row(Rule(style="dim"))
            body.add_row(Text("📋 Eventos", style="bold"))
            body.add_row(evlog_text)

            border = "cyan"
            if snap_devs:
                border = "green"
            return Panel(
                body,
                title=f"[bold {border}]● nRF24L01+ ESB Sniffer — {mode.upper()} — ACTIVO[/bold {border}]",
                subtitle="[dim]Ctrl-C para detener[/dim]",
                border_style=border,
                padding=(1, 2),
            )

        try:
            with Live(_build_panel(0), console=console, refresh_per_second=2) as live:
                while True:
                    time.sleep(0.5)
                    live.update(_build_panel(time.time() - start))
        except KeyboardInterrupt:
            pass
        finally:
            _running[0] = False
            t.join(timeout=2)
            if pcap_fh:
                pcap_fh.close()
            if json_fh:
                json_fh.close()

        total = len(devices_by_addr)
        UI.info(f"nRF24 Sniffer detenido. Detectados [bold]{total}[/bold] dispositivo(s).")
        if devices_by_addr:
            for addr_k, rec in devices_by_addr.items():
                UI.info(
                    f"  [bold cyan]{addr_k}[/bold cyan]  "
                    f"pkts={rec.pkts} acks={rec.acks} "
                    f"ch={sorted(rec.channels)} rssi_max={rec.rssi_max}"
                )
                if rec.keystrokes:
                    UI.info(
                        f"    [yellow]Keystrokes HID[/yellow]: "
                        f"{rec.decoded_string()!r}"
                    )
        if json_path:
            UI.info(f"Datos exportados a [bold]{json_path}[/bold]")

# ── Writer JSON Lines (.jsonl) ──────────────────────────────────────────────────────

class _JSONWriter:
    """
    Escribe frames capturados en JSON Lines (.jsonl).
    Cada línea es un objeto JSON independiente, fácil de procesar con
    jq, pandas, o cualquier herramienta de análisis.

    Esquema por línea:
      {"ts": 1711234567.89, "addr": "E7E7E7E7E7", "ch": 76, "rssi": -72,
        "plen": 8, "pid": 0, "no_ack": false, "payload": "AABBCCDD…",
        "crc_ok": true}   ← campo "hid" presente solo si decode_hid=yes

    Ejemplos de análisis offline:
      # Ver todos los keystrokes capturados:
      jq 'select(.hid != null) | .hid' captura.jsonl
      # Filtrar por dirección:
      jq 'select(.addr == "E7E7E7E7E7")' captura.jsonl
      # Cargar en pandas:
      import pandas as pd; df = pd.read_json("captura.jsonl", lines=True)
    """

    def __init__(self, path: str):
        self._f = open(path, "w", encoding="utf-8")

    def write_frame(self, addr: str, ch: int, rssi: int, plen: int,
                    pid: int, no_ack: bool, payload_hex: str,
                    crc_ok: bool, hid_decoded: str | None = None) -> None:
        record: dict = {
            "ts":      time.time(),
            "addr":    addr,
            "ch":      ch,
            "rssi":    rssi,
            "plen":    plen,
            "pid":     pid,
            "no_ack":  no_ack,
            "payload": payload_hex,
            "crc_ok":  crc_ok,
        }
        if hid_decoded is not None:
            record["hid"] = hid_decoded
        self._f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._f.flush()

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass

# ── Writer PCAP mínimo (LinkType = 147 = USER0, para frames raw ESB) ──────────

class _PCAPWriter:
    """
    Escribe un archivo PCAP con LinkType USER0 (DLT 147).
    Cada frame = payload ESB raw (sin preamble ni sync word).
    Abrir en Wireshark y en Edit→Preferences→Protocols→DLT_USER
    añadir disector 'nrf24' si está disponible, o analizar manualmente.
    """
    _GLOBAL_HDR = (
        b"\xd4\xc3\xb2\xa1"  # magic
        b"\x02\x00"           # major version 2
        b"\x04\x00"           # minor version 4
        b"\x00\x00\x00\x00"  # GMT offset
        b"\x00\x00\x00\x00"  # accuracy
        b"\xff\xff\x00\x00"  # snaplen 65535
        b"\x93\x00\x00\x00"  # DLT 147 = USER0 (nRF/ESB raw)
    )

    def __init__(self, path: str):
        self._f = open(path, "wb")
        self._f.write(self._GLOBAL_HDR)
        self._f.flush()

    def write_frame(self, payload: bytes, rssi: int, channel: int) -> None:
        """
        Escribe un frame PCAP.
        Prefijamos 2 bytes de metadata: [channel(1B)][rssi_offset(1B)]
        rssi_offset = (rssi + 128) & 0xFF  para mantener el signo.
        """
        meta = bytes([channel & 0xFF, (rssi + 128) & 0xFF])
        frame = meta + payload
        ts = time.time()
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        import struct
        hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        self._f.write(hdr + frame)
        self._f.flush()

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass
