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

import re
import select
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

    def update(self, ch: int, rssi: int, payload_hex: str = "",
               ack: bool = False, no_ack: bool = False, pid: int = -1):
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
            default="115200",
            type=str,
            choices=["9600", "115200", "500000"],
        ),
        AttackOption(
            name="export_pcap",
            description="Guardar paquetes en archivo PCAP (ruta, o vacío para no guardar)",
            default="",
            type=str,
        ),
    ]

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self, device) -> None:
        if self.get_option("flash") == "yes":
            UI.info(f"Flashing [bold]{self.firmware_alias}[/bold] onto {device}…")
            if not flash_firmware(self.firmware_alias, device.device_id):
                UI.error(
                    "Firmware flash failed.\n"
                    "  • El firmware nrf24-sniffer es CUSTOM — necesitas compilarlo primero.\n"
                    "  • Ver: [bold]firmware/nrf24_sniffer_cc1352p7/README.md[/bold]\n"
                    "  • Flashea el .hex resultante como un alias en catnip,\n"
                    "    o usa [bold]flash=no[/bold] si ya está en el dispositivo."
                )
                return
            UI.success("Firmware flashed.")
            time.sleep(2)

        mode    = self.get_option("mode")
        channel = self.get_option("channel").strip()
        rate    = self.get_option("rate")
        addr    = self.get_option("addr").upper().strip()
        baud    = int(self.get_option("baud"))
        pcap    = self.get_option("export_pcap").strip()

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

        self._run_sniffer(device, port, baud, initial_cmd, rate, mode, addr, pcap)

    # ── Sniffer loop ───────────────────────────────────────────────────────────

    def _run_sniffer(self, device, port, baud: int,
                     initial_cmd: str, rate: str, mode: str,
                     addr: str, pcap_path: str) -> None:

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
                with lock:
                    if a not in devices_by_addr:
                        devices_by_addr[a] = _DeviceRecord(a)
                    devices_by_addr[a].update(ch, rssi, pld, no_ack=noack, pid=pid)
                if pcap_fh:
                    try:
                        pcap_fh.write_frame(bytes.fromhex(pld) if pld else b"",
                                             rssi, ch)
                    except Exception:
                        pass
                _log_event(
                    f"[cyan]{a}[/cyan] ch={ch} plen={plen} pid={pid} "
                    f"crc=[{'green' if crc == 'OK' else 'red'}]{crc}[/{'green' if crc == 'OK' else 'red'}]"
                )
                return

            # [ACK] — acknowledge vacío
            m = _ACK_RE.search(line)
            if m:
                ch   = int(m.group(1))
                rssi = int(m.group(2))
                a    = m.group(3).upper()
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
            dev_tbl = Table(
                "Address", "Ch(s)", "Pkts", "ACKs", "RSSI now", "RSSI max",
                "Last payload", "First", "Last",
                box=None, show_header=True,
                header_style="bold dim",
                padding=(0, 1),
            )
            for rec in snap_devs:
                chs = ",".join(str(c) for c in sorted(rec.channels)[:5])
                pld_preview = (rec.payloads[-1][:20] + "…") if rec.payloads else "[dim]—[/dim]"
                dev_tbl.add_row(
                    f"[bold cyan]{rec.addr}[/bold cyan]",
                    chs or "?",
                    str(rec.pkts),
                    str(rec.acks),
                    f"{rec.rssi_last} dBm",
                    f"{rec.rssi_max} dBm",
                    pld_preview,
                    rec.first_seen,
                    rec.last_seen,
                )

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

        total = len(devices_by_addr)
        UI.info(f"nRF24 Sniffer detenido. Detectados [bold]{total}[/bold] dispositivo(s).")
        if devices_by_addr:
            for addr_k, rec in devices_by_addr.items():
                UI.info(
                    f"  [bold cyan]{addr_k}[/bold cyan]  "
                    f"pkts={rec.pkts} acks={rec.acks} "
                    f"ch={sorted(rec.channels)} rssi_max={rec.rssi_max}"
                )


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
