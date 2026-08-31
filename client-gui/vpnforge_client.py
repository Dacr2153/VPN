#!/usr/bin/env python3
"""
VPNForge Client GUI
Phase 5: PySide6-based desktop client

Architecture:
  - MainWindow with system tray integration
  - gRPC client via grpc.aio (connects to vpnd Unix socket)
  - Connection panel: profile selection, connect/disconnect button
  - Live metrics panel: bandwidth, latency, jitter gauges
  - Status bar with connection indicator (colored)
  - Settings dialog for advanced options
  - Notification area icon with menu

Security:
  - Unix socket connection only (no network exposure)
  - All sensitive config passed through shared config files, never via UI
  - Profile names validated server-side via gRPC
"""

import sys
import os
import asyncio
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Attempt PySide6, fall back to helpful error ───────────────────────────────
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QComboBox, QProgressBar, QSystemTrayIcon,
        QMenu, QDialog, QFormLayout, QLineEdit, QCheckBox, QGroupBox,
        QScrollArea, QFrame, QSplitter, QTabWidget, QTextEdit,
        QMessageBox, QFileDialog, QToolBar, QStatusBar,
    )
    from PySide6.QtCore import (
        Qt, QTimer, QThread, Signal, QObject, Slot, QSize,
        QPropertyAnimation, QEasingCurve,
    )
    from PySide6.QtGui import (
        QIcon, QPixmap, QColor, QPainter, QAction, QFont,
        QLinearGradient, QPalette,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False

# ── PySide6-Charts (real-time graphs, optional) ──────────────────────────────
try:
    from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
    from PySide6.QtCore import QPointF
    HAS_CHARTS = True
except ImportError:
    HAS_CHARTS = False

# ── gRPC client (generated stubs) ────────────────────────────────────────────
try:
    import grpc
    import grpc.aio
    # When installed properly, these come from the proto generation step
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────
APP_NAME = "VPNForge"
APP_VERSION = "0.1.0"
SOCKET_PATH = "/run/vpnd/control.sock"
SOCKET_PATH_DEV = "/tmp/vpnd.sock"
RECONNECT_INTERVAL_MS = 2000      # retry gRPC connection every 2s
METRICS_INTERVAL_MS = 1000        # refresh live metrics every 1s
CHART_HISTORY = 60                # seconds of rolling data to show

# ── Color palette (dark theme) ────────────────────────────────────────────────
COLORS = {
    "bg_dark":      "#1a1a2e",
    "bg_panel":     "#16213e",
    "bg_card":      "#0f3460",
    "accent":       "#e94560",
    "accent_green": "#4caf50",
    "accent_amber": "#ff9800",
    "text_primary": "#eaeaea",
    "text_dimmed":  "#9e9e9e",
    "connected":    "#4caf50",
    "disconnected": "#f44336",
    "connecting":   "#ff9800",
}

STYLESHEET = f"""
QMainWindow, QDialog, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: "JetBrains Mono", "Fira Code", monospace;
    font-size: 13px;
}}
QPushButton {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['accent']};
    border-radius: 6px;
    padding: 8px 20px;
    font-weight: bold;
}}
QPushButton:hover {{
    background-color: {COLORS['accent']};
}}
QPushButton#connect_btn {{
    background-color: {COLORS['accent_green']};
    border-color: {COLORS['accent_green']};
    font-size: 15px;
    padding: 12px 30px;
}}
QPushButton#connect_btn:hover {{
    background-color: #388e3c;
}}
QPushButton#disconnect_btn {{
    background-color: {COLORS['disconnected']};
    border-color: {COLORS['disconnected']};
    font-size: 15px;
    padding: 12px 30px;
}}
QComboBox {{
    background-color: {COLORS['bg_panel']};
    border: 1px solid {COLORS['bg_card']};
    border-radius: 4px;
    padding: 6px;
    color: {COLORS['text_primary']};
}}
QLabel#status_indicator {{
    font-size: 16px;
    font-weight: bold;
    padding: 8px;
    border-radius: 6px;
}}
QGroupBox {{
    border: 1px solid {COLORS['bg_card']};
    border-radius: 8px;
    margin-top: 12px;
    padding: 10px;
}}
QGroupBox::title {{
    color: {COLORS['accent']};
    font-weight: bold;
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}}
QProgressBar {{
    background-color: {COLORS['bg_panel']};
    border: 1px solid {COLORS['bg_card']};
    border-radius: 4px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {COLORS['accent']};
    border-radius: 4px;
}}
QTextEdit {{
    background-color: {COLORS['bg_panel']};
    border: 1px solid {COLORS['bg_card']};
    border-radius: 4px;
    color: {COLORS['text_primary']};
    font-family: monospace;
}}
QTabWidget::pane {{
    border: 1px solid {COLORS['bg_card']};
    background-color: {COLORS['bg_panel']};
}}
QTabBar::tab {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_dimmed']};
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}}
QTabBar::tab:selected {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border-bottom: 2px solid {COLORS['accent']};
}}
QStatusBar {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_dimmed']};
}}
"""


# ── Connection state enum ─────────────────────────────────────────────────────
class ConnectionState:
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    ERROR        = "error"


# ── Metrics data class ────────────────────────────────────────────────────────
class VpnMetrics:
    def __init__(self):
        self.bytes_sent       = 0
        self.bytes_received   = 0
        self.rtt_ms           = 0.0
        self.jitter_ms        = 0.0
        self.loss_percent     = 0.0
        self.rx_rate_bps      = 0.0
        self.tx_rate_bps      = 0.0
        self.protocol         = "—"
        self.interface        = "—"
        self.uptime_secs      = 0
        self.virtual_ip       = "—"
        self.server_ip        = "—"


def _fmt_bytes(n: int) -> str:
    """Format byte count to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_rate(bps: float) -> str:
    return _fmt_bytes(int(bps)) + "/s"


def _fmt_uptime(secs: int) -> str:
    d = timedelta(seconds=secs)
    h, rem = divmod(d.seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d.days:
        parts.append(f"{d.days}d")
    parts.extend([f"{h:02d}h", f"{m:02d}m", f"{s:02d}s"])
    return " ".join(parts)


# ── gRPC worker (runs in background thread with its own event loop) ───────────
class GrpcWorker(QObject):
    """
    Background worker that maintains the gRPC connection and emits signals
    when status / metrics change.  Runs in a dedicated QThread so Qt UI
    never blocks.
    """
    status_changed  = Signal(str, str)  # (state: ConnectionState, detail: str)
    metrics_updated = Signal(object)    # VpnMetrics
    profiles_loaded = Signal(list)      # list[str]
    error_occurred  = Signal(str)

    def __init__(self, socket_path: str):
        super().__init__()
        self._socket_path = socket_path
        self._channel = None
        self._stub = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @Slot()
    def start(self):
        """Called when the QThread starts."""
        self._running = True
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main_loop())
        finally:
            self._loop.close()

    @Slot()
    def stop(self):
        self._running = False

    async def _connect_channel(self):
        """Open the gRPC channel over the Unix domain socket."""
        if not GRPC_AVAILABLE:
            self.error_occurred.emit("grpcio not installed: pip install grpcio grpcio-tools")
            return None

        # Use the dev socket if the production socket doesn't exist
        path = self._socket_path
        if not Path(path).exists():
            path = SOCKET_PATH_DEV

        channel = grpc.aio.insecure_channel(f"unix://{path}")
        try:
            await asyncio.wait_for(channel.channel_ready(), timeout=3.0)
            return channel
        except (asyncio.TimeoutError, grpc.aio.AioRpcError):
            await channel.close()
            return None

    async def _main_loop(self):
        """Periodically poll daemon status and stream metrics."""
        while self._running:
            channel = await self._connect_channel()
            if channel is None:
                self.status_changed.emit(ConnectionState.DISCONNECTED, "Daemon not reachable")
                await asyncio.sleep(RECONNECT_INTERVAL_MS / 1000)
                continue

            # Import generated stubs (deferred to avoid import errors when grpc not installed)
            try:
                from vpnd_pb2_grpc import VpndServiceStub  # type: ignore
                stub = VpndServiceStub(channel)
                await self._poll_loop(stub)
            except ImportError:
                self.error_occurred.emit(
                    "Proto stubs not generated.\nRun: make proto\n(requires protoc and grpc_tools)"
                )
                await asyncio.sleep(5)
            except Exception as e:
                self.error_occurred.emit(str(e))
                await asyncio.sleep(2)
            finally:
                await channel.close()

    async def _poll_loop(self, stub):
        """Poll daemon every second for status and metrics."""
        import vpnd_pb2  # type: ignore
        while self._running:
            try:
                # Get status
                resp = await asyncio.wait_for(stub.GetStatus(vpnd_pb2.Empty()), timeout=2.0)
                state = ConnectionState.CONNECTED if resp.connected else ConnectionState.DISCONNECTED
                detail = f"{resp.profile_name} — {resp.virtual_ip}" if resp.connected else "Not connected"
                self.status_changed.emit(state, detail)

                # Get metrics
                metrics_resp = await asyncio.wait_for(
                    stub.GetStatus(vpnd_pb2.Empty()), timeout=2.0
                )
                m = VpnMetrics()
                m.virtual_ip = resp.virtual_ip
                m.server_ip  = resp.server_ip
                m.protocol   = resp.protocol
                m.uptime_secs = resp.uptime_seconds
                self.metrics_updated.emit(m)

                # Refresh profile list every 10 seconds
                await asyncio.sleep(METRICS_INTERVAL_MS / 1000)
            except (asyncio.TimeoutError, Exception):
                self.status_changed.emit(ConnectionState.DISCONNECTED, "Lost connection to daemon")
                await asyncio.sleep(2)
                return

    def connect_vpn(self, profile_name: str):
        """Trigger a VPN connection from the UI thread."""
        if self._loop and self._running:
            asyncio.run_coroutine_threadsafe(self._do_connect(profile_name), self._loop)

    def disconnect_vpn(self):
        if self._loop and self._running:
            asyncio.run_coroutine_threadsafe(self._do_disconnect(), self._loop)

    async def _do_connect(self, profile_name: str):
        pass  # Will call stub.ConnectVpn(ConnectRequest(profile_name=profile_name))

    async def _do_disconnect(self):
        pass  # Will call stub.Disconnect(DisconnectRequest())


# ── Status indicator widget ───────────────────────────────────────────────────
class StatusIndicator(QLabel):
    """Circular colored indicator for connection state."""

    STATE_COLORS = {
        ConnectionState.CONNECTED:    COLORS["connected"],
        ConnectionState.CONNECTING:   COLORS["connecting"],
        ConnectionState.DISCONNECTED: COLORS["disconnected"],
        ConnectionState.ERROR:        COLORS["disconnected"],
    }

    STATE_LABELS = {
        ConnectionState.CONNECTED:    "● CONNECTED",
        ConnectionState.CONNECTING:   "◌ CONNECTING...",
        ConnectionState.DISCONNECTED: "○ DISCONNECTED",
        ConnectionState.ERROR:        "⚠ ERROR",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("status_indicator")
        self.setAlignment(Qt.AlignCenter)
        self.set_state(ConnectionState.DISCONNECTED)

    def set_state(self, state: str):
        color = self.STATE_COLORS.get(state, COLORS["disconnected"])
        self.setText(self.STATE_LABELS.get(state, "○ UNKNOWN"))
        self.setStyleSheet(f"""
            QLabel#status_indicator {{
                color: {color};
                font-size: 16px;
                font-weight: bold;
                padding: 8px;
            }}
        """)


# ── Real-time bandwidth chart ────────────────────────────────────────────────
class BandwidthChart(QWidget):
    """Rolling line chart showing download/upload rates over CHART_HISTORY seconds."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if not HAS_CHARTS:
            self._rx_lbl = QLabel("↓ 0 B/s")
            self._tx_lbl = QLabel("↑ 0 B/s")
            for lbl in (self._rx_lbl, self._tx_lbl):
                lbl.setAlignment(Qt.AlignCenter)
                lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 15px;")
                layout.addWidget(lbl)
            layout.addWidget(QLabel(
                "(Install PySide6-Charts for live graphs: pip install PySide6-Charts)",
            ))
            return

        from collections import deque
        self._rx_buf: list = []
        self._tx_buf: list = []

        self._rx_series = QLineSeries()
        self._tx_series = QLineSeries()
        self._rx_series.setName("↓ Download")
        self._tx_series.setName("↑ Upload")

        pen_rx = self._rx_series.pen()
        pen_rx.setColor(QColor(COLORS["accent_green"]))
        pen_rx.setWidth(2)
        self._rx_series.setPen(pen_rx)

        pen_tx = self._tx_series.pen()
        pen_tx.setColor(QColor(COLORS["accent"]))
        pen_tx.setWidth(2)
        self._tx_series.setPen(pen_tx)

        chart = QChart()
        chart.addSeries(self._rx_series)
        chart.addSeries(self._tx_series)
        chart.setTitle("Bandwidth")
        chart.setBackgroundBrush(QColor(COLORS["bg_panel"]))
        chart.setTitleBrush(QColor(COLORS["text_primary"]))
        chart.legend().setLabelColor(QColor(COLORS["text_primary"]))

        self._axis_x = QValueAxis()
        self._axis_x.setRange(0, CHART_HISTORY)
        self._axis_x.setLabelFormat("%d s")
        self._axis_x.setLabelsColor(QColor(COLORS["text_dimmed"]))
        self._axis_x.setGridLineColor(QColor(COLORS["bg_card"]))

        self._axis_y = QValueAxis()
        self._axis_y.setRange(0, 512)
        self._axis_y.setLabelFormat("%.0f KB/s")
        self._axis_y.setLabelsColor(QColor(COLORS["text_dimmed"]))
        self._axis_y.setGridLineColor(QColor(COLORS["bg_card"]))

        chart.addAxis(self._axis_x, Qt.AlignBottom)
        chart.addAxis(self._axis_y, Qt.AlignLeft)
        self._rx_series.attachAxis(self._axis_x)
        self._rx_series.attachAxis(self._axis_y)
        self._tx_series.attachAxis(self._axis_x)
        self._tx_series.attachAxis(self._axis_y)

        view = QChartView(chart)
        layout.addWidget(view)

    def push(self, rx_bps: float, tx_bps: float):
        if not HAS_CHARTS:
            if hasattr(self, "_rx_lbl"):
                self._rx_lbl.setText(f"↓ {_fmt_rate(rx_bps)}")
                self._tx_lbl.setText(f"↑ {_fmt_rate(tx_bps)}")
            return

        rx_kb = rx_bps / 1024.0
        tx_kb = tx_bps / 1024.0
        self._rx_buf.append(rx_kb)
        self._tx_buf.append(tx_kb)
        if len(self._rx_buf) > CHART_HISTORY:
            self._rx_buf.pop(0)
            self._tx_buf.pop(0)

        self._rx_series.clear()
        self._tx_series.clear()
        start = float(CHART_HISTORY - len(self._rx_buf))
        for i, (r, t) in enumerate(zip(self._rx_buf, self._tx_buf)):
            self._rx_series.append(QPointF(start + i, r))
            self._tx_series.append(QPointF(start + i, t))

        peak = max(max(self._rx_buf, default=0), max(self._tx_buf, default=0))
        self._axis_y.setRange(0, max(peak * 1.25, 1.0))


class LatencyChart(QWidget):
    """Rolling line chart showing RTT latency over CHART_HISTORY data-points."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if not HAS_CHARTS:
            self._lbl = QLabel("Latency: — ms")
            self._lbl.setAlignment(Qt.AlignCenter)
            self._lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 15px;")
            layout.addWidget(self._lbl)
            return

        self._buf: list = []
        self._series = QLineSeries()
        self._series.setName("RTT (ms)")
        pen = self._series.pen()
        pen.setColor(QColor(COLORS["accent_amber"]))
        pen.setWidth(2)
        self._series.setPen(pen)

        chart = QChart()
        chart.addSeries(self._series)
        chart.setTitle("Latency")
        chart.setBackgroundBrush(QColor(COLORS["bg_panel"]))
        chart.setTitleBrush(QColor(COLORS["text_primary"]))
        chart.legend().setLabelColor(QColor(COLORS["text_primary"]))

        self._axis_x = QValueAxis()
        self._axis_x.setRange(0, CHART_HISTORY)
        self._axis_x.setLabelFormat("%d")
        self._axis_x.setLabelsColor(QColor(COLORS["text_dimmed"]))
        self._axis_x.setGridLineColor(QColor(COLORS["bg_card"]))

        self._axis_y = QValueAxis()
        self._axis_y.setRange(0, 200)
        self._axis_y.setLabelFormat("%.0f ms")
        self._axis_y.setLabelsColor(QColor(COLORS["text_dimmed"]))
        self._axis_y.setGridLineColor(QColor(COLORS["bg_card"]))

        chart.addAxis(self._axis_x, Qt.AlignBottom)
        chart.addAxis(self._axis_y, Qt.AlignLeft)
        self._series.attachAxis(self._axis_x)
        self._series.attachAxis(self._axis_y)

        view = QChartView(chart)
        layout.addWidget(view)

    def push(self, rtt_ms: float):
        if not HAS_CHARTS:
            if hasattr(self, "_lbl"):
                self._lbl.setText(f"Latency: {rtt_ms:.1f} ms")
            return
        self._buf.append(rtt_ms)
        if len(self._buf) > CHART_HISTORY:
            self._buf.pop(0)
        self._series.clear()
        start = float(CHART_HISTORY - len(self._buf))
        for i, v in enumerate(self._buf):
            self._series.append(QPointF(start + i, v))
        peak = max(self._buf, default=1.0)
        self._axis_y.setRange(0, max(peak * 1.3, 10))


# ── Metrics card widget ───────────────────────────────────────────────────────
class MetricsCard(QGroupBox):
    def __init__(self, title: str, parent=None):
        super().__init__(title, parent)
        self._layout = QFormLayout()
        self.setLayout(self._layout)
        self._labels: dict[str, QLabel] = {}

    def add_row(self, key: str, initial: str = "—") -> QLabel:
        label = QLabel(initial)
        label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        self._layout.addRow(QLabel(key), label)
        self._labels[key] = label
        return label

    def update_row(self, key: str, value: str):
        if key in self._labels:
            self._labels[key].setText(value)


# ── Main window ───────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(800, 600)
        self._state = ConnectionState.DISCONNECTED

        # Build UI
        self._build_ui()
        self._setup_tray()
        self._setup_worker()

        # Metrics refresh timer
        self._metrics_timer = QTimer()
        self._metrics_timer.timeout.connect(self._refresh_uptime)
        self._metrics_timer.start(1000)

        self.setStyleSheet(STYLESHEET)

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(12)
        root.setContentsMargins(16, 16, 16, 16)

        # Header
        header = self._make_header()
        root.addWidget(header)

        # Tabs
        tabs = QTabWidget()
        tabs.addTab(self._make_connect_tab(), "  Connect  ")
        tabs.addTab(self._make_metrics_tab(), "  Metrics  ")
        tabs.addTab(self._make_logs_tab(),    "  Logs  ")
        root.addWidget(tabs)

        # Status bar
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_bar_label = QLabel("Ready")
        sb.addWidget(self._status_bar_label)

    def _make_header(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)

        title = QLabel(f"<b>{APP_NAME}</b>")
        title.setStyleSheet(f"font-size: 20px; color: {COLORS['accent']};")

        self._status_indicator = StatusIndicator()
        h.addWidget(title)
        h.addStretch()
        h.addWidget(self._status_indicator)
        return w

    def _make_connect_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setSpacing(16)

        # Profile selection
        profile_group = QGroupBox("VPN Profile")
        pg = QFormLayout()
        self._profile_combo = QComboBox()
        self._profile_combo.addItem("(loading profiles...)")
        self._profile_combo.setMinimumWidth(300)
        pg.addRow("Profile:", self._profile_combo)
        profile_group.setLayout(pg)
        vbox.addWidget(profile_group)

        # Connection detail card
        self._conn_card = MetricsCard("Connection")
        self._conn_card.add_row("Virtual IP:")
        self._conn_card.add_row("Server IP:")
        self._conn_card.add_row("Protocol:")
        self._conn_card.add_row("Uptime:")
        vbox.addWidget(self._conn_card)

        # Connect button
        btn_row = QHBoxLayout()
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setObjectName("connect_btn")
        self._connect_btn.setMinimumHeight(48)
        self._connect_btn.clicked.connect(self._on_connect_clicked)
        btn_row.addStretch()
        btn_row.addWidget(self._connect_btn)
        btn_row.addStretch()
        vbox.addLayout(btn_row)

        # Kill switch toggle
        ks_row = QHBoxLayout()
        self._kill_switch_cb = QCheckBox("Enable Kill Switch  (block all traffic if VPN drops)")
        self._kill_switch_cb.setStyleSheet(f"color: {COLORS['text_dimmed']};")
        ks_row.addWidget(self._kill_switch_cb)
        vbox.addLayout(ks_row)

        vbox.addStretch()
        return w

    def _make_metrics_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setSpacing(10)

        # Totals row (compact cards)
        totals_row = QHBoxLayout()

        traffic = MetricsCard("Traffic Totals")
        self._rx_label = traffic.add_row("↓ Download:")
        self._tx_label = traffic.add_row("↑ Upload:")
        self._rx_rate_label = traffic.add_row("↓ Rate:")
        self._tx_rate_label = traffic.add_row("↑ Rate:")
        totals_row.addWidget(traffic)

        quality = MetricsCard("Quality")
        self._rtt_label    = quality.add_row("Latency (RTT):")
        self._jitter_label = quality.add_row("Jitter:")
        self._loss_label   = quality.add_row("Packet Loss:")
        totals_row.addWidget(quality)

        vbox.addLayout(totals_row)

        # Live charts
        charts_row = QHBoxLayout()

        bw_group = QGroupBox("Bandwidth (KB/s)")
        bw_layout = QVBoxLayout(bw_group)
        self._bw_chart = BandwidthChart()
        bw_layout.addWidget(self._bw_chart)
        charts_row.addWidget(bw_group, 3)

        lat_group = QGroupBox("Latency (ms)")
        lat_layout = QVBoxLayout(lat_group)
        self._lat_chart = LatencyChart()
        lat_layout.addWidget(self._lat_chart)
        charts_row.addWidget(lat_group, 2)

        vbox.addLayout(charts_row)
        return w

    def _make_logs_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setFont(QFont("monospace", 11))
        vbox.addWidget(self._log_text)
        return w

    # ── System tray ──────────────────────────────────────────────────────────

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self._tray = QSystemTrayIcon(self)
        self._tray.setToolTip(APP_NAME)

        # Create a simple colored icon for the tray
        pix = QPixmap(22, 22)
        pix.fill(QColor(COLORS["disconnected"]))
        self._tray.setIcon(QIcon(pix))

        menu = QMenu()
        menu.addAction("Show", self.show)
        menu.addSeparator()
        menu.addAction("Connect", self._on_connect_clicked)
        menu.addAction("Disconnect", self._on_disconnect_clicked)
        menu.addSeparator()
        menu.addAction("Quit", QApplication.instance().quit)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show() if self.isHidden() else self.hide()

    # ── Worker / signals ─────────────────────────────────────────────────────

    def _setup_worker(self):
        self._worker = GrpcWorker(SOCKET_PATH)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.status_changed.connect(self._on_status_changed)
        self._worker.metrics_updated.connect(self._on_metrics_updated)
        self._worker.error_occurred.connect(self._on_error)
        self._thread.start()

    # ── Slots ────────────────────────────────────────────────────────────────

    @Slot(str, str)
    def _on_status_changed(self, state: str, detail: str):
        self._state = state
        self._status_indicator.set_state(state)
        self._status_bar_label.setText(detail)
        self._log(f"[{datetime.now():%H:%M:%S}] Status: {state} — {detail}")

        if state == ConnectionState.CONNECTED:
            self._connect_btn.setText("Disconnect")
            self._connect_btn.setObjectName("disconnect_btn")
            self._connect_btn.setStyleSheet("")
            self._connect_btn.clicked.disconnect()
            self._connect_btn.clicked.connect(self._on_disconnect_clicked)
        else:
            self._connect_btn.setText("Connect")
            self._connect_btn.setObjectName("connect_btn")
            self._connect_btn.setStyleSheet("")
            try:
                self._connect_btn.clicked.disconnect()
            except RuntimeError:
                pass
            self._connect_btn.clicked.connect(self._on_connect_clicked)

        # Update tray icon color
        if hasattr(self, "_tray"):
            color = {
                ConnectionState.CONNECTED:    COLORS["connected"],
                ConnectionState.CONNECTING:   COLORS["connecting"],
                ConnectionState.DISCONNECTED: COLORS["disconnected"],
            }.get(state, COLORS["disconnected"])
            pix = QPixmap(22, 22)
            pix.fill(QColor(color))
            self._tray.setIcon(QIcon(pix))
        self.setStyleSheet(STYLESHEET)

    @Slot(object)
    def _on_metrics_updated(self, m: VpnMetrics):
        self._conn_card.update_row("Virtual IP:", m.virtual_ip)
        self._conn_card.update_row("Server IP:", m.server_ip)
        self._conn_card.update_row("Protocol:", m.protocol)
        self._conn_card.update_row("Uptime:", _fmt_uptime(m.uptime_secs))

        self._rx_label.setText(_fmt_bytes(m.bytes_received))
        self._tx_label.setText(_fmt_bytes(m.bytes_sent))
        self._rx_rate_label.setText(_fmt_rate(m.rx_rate_bps))
        self._tx_rate_label.setText(_fmt_rate(m.tx_rate_bps))
        self._rtt_label.setText(f"{m.rtt_ms:.1f} ms")
        self._jitter_label.setText(f"{m.jitter_ms:.1f} ms")
        self._loss_label.setText(f"{m.loss_percent:.1f}%")
        # Update live charts
        self._bw_chart.push(m.rx_rate_bps, m.tx_rate_bps)
        self._lat_chart.push(m.rtt_ms)

    @Slot(str)
    def _on_error(self, msg: str):
        self._log(f"[ERROR] {msg}")
        self._status_bar_label.setText(f"Error: {msg[:60]}")

    @Slot()
    def _on_connect_clicked(self):
        profile = self._profile_combo.currentText()
        if not profile or profile.startswith("("):
            QMessageBox.warning(self, "No Profile", "Please select a VPN profile first.")
            return
        self._status_indicator.set_state(ConnectionState.CONNECTING)
        self._log(f"[{datetime.now():%H:%M:%S}] Connecting to profile: {profile}")
        self._worker.connect_vpn(profile)

    @Slot()
    def _on_disconnect_clicked(self):
        self._log(f"[{datetime.now():%H:%M:%S}] Disconnecting...")
        self._worker.disconnect_vpn()

    def _refresh_uptime(self):
        """Called by timer to update uptime display without a full RPC call."""
        pass  # Handled by metrics update signal

    def _log(self, msg: str):
        self._log_text.append(msg)

    def closeEvent(self, event):
        if hasattr(self, "_tray") and self._tray.isVisible():
            self.hide()
            event.ignore()
        else:
            self._worker.stop()
            self._thread.quit()
            self._thread.wait(2000)
            event.accept()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    if not HAS_PYSIDE6:
        print("ERROR: PySide6 is not installed.")
        print("Install with: pip install PySide6 grpcio grpcio-tools")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setQuitOnLastWindowClosed(False)  # Keep alive in system tray

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
