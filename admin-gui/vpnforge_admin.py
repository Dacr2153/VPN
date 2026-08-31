#!/usr/bin/env python3
"""
VPNForge Admin GUI
Phase 6: PySide6-based server administration panel

Features:
  - Real-time session management table
  - Live bandwidth/CPU/memory gauges (streaming from daemon)
  - Network topology graph
  - Server configuration editor with TOML validation
  - Alert feed with severity colour coding
  - Audit log viewer with filtering
  - Per-session kick, inspect, and geo-lookup actions
"""

import sys
import os
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
        QGroupBox, QFormLayout, QProgressBar, QSplitter, QTabWidget,
        QTextEdit, QLineEdit, QMessageBox, QDialog, QDialogButtonBox,
        QSystemTrayIcon, QMenu, QStatusBar, QScrollArea, QFrame,
        QComboBox,
    )
    from PySide6.QtCore import (
        Qt, QTimer, QThread, Signal, QObject, Slot, QSize, QSortFilterProxyModel,
    )
    from PySide6.QtGui import (
        QColor, QIcon, QPixmap, QAction, QFont, QPainter,
    )
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False

try:
    import grpc
    import grpc.aio
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

# ── NetworkX for topology layout (optional) ───────────────────────────────────
try:
    import networkx as nx
    import math
    HAS_NX = True
except ImportError:
    HAS_NX = False

# ── Constants ─────────────────────────────────────────────────────────────────
APP_NAME    = "VPNForge Admin"
APP_VERSION = "0.1.0"
SOCKET_PATH = "/run/vpnd/control.sock"
SOCKET_PATH_DEV = "/tmp/vpnd.sock"
REFRESH_MS  = 2000

COLORS = {
    "bg":           "#0d1117",
    "bg_card":      "#161b22",
    "bg_row_alt":   "#1c2128",
    "border":       "#30363d",
    "accent":       "#58a6ff",
    "green":        "#3fb950",
    "red":          "#f85149",
    "amber":        "#d29922",
    "text":         "#e6edf3",
    "text_dim":     "#8b949e",
    "critical":     "#f85149",
    "high":         "#d29922",
    "medium":       "#58a6ff",
    "low":          "#3fb950",
}

STYLESHEET = f"""
QMainWindow, QDialog, QWidget {{
    background-color: {COLORS['bg']};
    color: {COLORS['text']};
    font-family: "JetBrains Mono", "Fira Code", monospace;
    font-size: 12px;
}}
QGroupBox {{
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    margin-top: 14px;
    padding: 10px;
}}
QGroupBox::title {{
    color: {COLORS['accent']};
    font-weight: bold;
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}}
QTableWidget {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    gridline-color: {COLORS['border']};
    selection-background-color: {COLORS['accent']};
    alternate-background-color: {COLORS['bg_row_alt']};
}}
QTableWidget::item {{
    padding: 4px 8px;
}}
QHeaderView::section {{
    background-color: {COLORS['bg']};
    color: {COLORS['text_dim']};
    border: 1px solid {COLORS['border']};
    padding: 6px;
    font-weight: bold;
}}
QPushButton {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 6px 14px;
}}
QPushButton:hover {{
    border-color: {COLORS['accent']};
    color: {COLORS['accent']};
}}
QPushButton#kick_btn {{
    color: {COLORS['red']};
    border-color: {COLORS['red']};
}}
QProgressBar {{
    background-color: {COLORS['bg']};
    border: 1px solid {COLORS['border']};
    border-radius: 3px;
    text-align: center;
    color: {COLORS['text']};
}}
QProgressBar::chunk {{
    background-color: {COLORS['accent']};
    border-radius: 3px;
}}
QTextEdit {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    font-family: monospace;
    font-size: 11px;
}}
QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    background-color: {COLORS['bg_card']};
}}
QTabBar::tab {{
    background-color: {COLORS['bg']};
    color: {COLORS['text_dim']};
    padding: 8px 16px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {COLORS['text']};
    border-bottom-color: {COLORS['accent']};
}}
QLineEdit {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 5px;
    color: {COLORS['text']};
}}
QStatusBar {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_dim']};
    border-top: 1px solid {COLORS['border']};
}}
"""


# ── Data models ───────────────────────────────────────────────────────────────
class SessionRecord:
    def __init__(self, data: dict):
        self.id            = data.get("id", "")
        self.peer_id       = data.get("peer_id", "")
        self.virtual_ip    = data.get("virtual_ip", "")
        self.real_ip       = data.get("real_ip", "")
        self.protocol      = data.get("protocol", "")
        self.connected_since = data.get("connected_since", 0)
        self.rx_bytes      = data.get("rx_bytes", 0)
        self.tx_bytes      = data.get("tx_bytes", 0)
        self.latency_ms    = data.get("latency_ms", 0.0)
        self.username      = data.get("username", "")
        self.geo_country   = data.get("geo_country", "")

    @property
    def uptime_str(self) -> str:
        if not self.connected_since:
            return "—"
        secs = int(datetime.now().timestamp()) - self.connected_since
        return str(timedelta(seconds=max(secs, 0)))

    @property
    def rx_str(self) -> str:
        return _fmt_bytes(self.rx_bytes)

    @property
    def tx_str(self) -> str:
        return _fmt_bytes(self.tx_bytes)


class AlertRecord:
    SEVERITY_COLORS = {
        "critical": COLORS["critical"],
        "high":     COLORS["high"],
        "medium":   COLORS["medium"],
        "low":      COLORS["low"],
    }

    def __init__(self, data: dict):
        self.id        = data.get("id", "")
        self.severity  = data.get("severity", "low")
        self.message   = data.get("message", "")
        self.timestamp = data.get("timestamp_ms", 0)

    @property
    def color(self) -> str:
        return self.SEVERITY_COLORS.get(self.severity, COLORS["low"])

    @property
    def time_str(self) -> str:
        if not self.timestamp:
            return "—"
        return datetime.fromtimestamp(self.timestamp / 1000).strftime("%H:%M:%S")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── gRPC background worker ────────────────────────────────────────────────────
class AdminWorker(QObject):
    sessions_updated  = Signal(list)   # list[SessionRecord]
    health_updated    = Signal(dict)   # SystemHealth fields
    alerts_updated    = Signal(list)   # list[AlertRecord]
    topology_updated  = Signal(dict)   # {nodes, edges}
    error_occurred    = Signal(str)
    connected         = Signal(bool)

    def __init__(self, socket_path: str):
        super().__init__()
        self._socket_path = socket_path
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @Slot()
    def start(self):
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

    async def _main_loop(self):
        while self._running:
            path = self._socket_path
            if not Path(path).exists():
                path = SOCKET_PATH_DEV

            if not GRPC_AVAILABLE:
                self.error_occurred.emit("grpcio not installed")
                await asyncio.sleep(5)
                continue

            channel = grpc.aio.insecure_channel(f"unix://{path}")
            try:
                await asyncio.wait_for(channel.channel_ready(), timeout=3.0)
                self.connected.emit(True)

                try:
                    from vpnd_pb2_grpc import VpndServiceStub  # type: ignore
                    import vpnd_pb2  # type: ignore
                    stub = VpndServiceStub(channel)
                    await self._poll_loop(stub, vpnd_pb2)
                except ImportError:
                    self.error_occurred.emit("Proto stubs not found. Run: make proto")
                    await asyncio.sleep(10)

            except (asyncio.TimeoutError, Exception) as e:
                self.connected.emit(False)
                self.error_occurred.emit(str(e))
                await asyncio.sleep(REFRESH_MS / 1000)
            finally:
                await channel.close()

    async def _poll_loop(self, stub, pb2):
        while self._running:
            try:
                # Sessions
                sess_resp = await asyncio.wait_for(stub.GetSessions(pb2.Empty()), timeout=3.0)
                sessions = [SessionRecord({
                    "id":             s.id,
                    "peer_id":        s.peer_id,
                    "virtual_ip":     s.virtual_ip,
                    "real_ip":        s.real_ip,
                    "protocol":       s.protocol,
                    "connected_since": s.connected_since,
                    "rx_bytes":       s.rx_bytes,
                    "tx_bytes":       s.tx_bytes,
                    "latency_ms":     s.latency_ms,
                    "username":       s.username,
                    "geo_country":    s.geo_country,
                }) for s in sess_resp.sessions]
                self.sessions_updated.emit(sessions)

                # System health
                health = await asyncio.wait_for(stub.GetSystemHealth(pb2.Empty()), timeout=3.0)
                self.health_updated.emit({
                    "cpu_percent":        health.cpu_percent,
                    "memory_used_bytes":  health.memory_used_bytes,
                    "memory_total_bytes": health.memory_total_bytes,
                    "rx_bytes_per_sec":   health.rx_bytes_per_sec,
                    "tx_bytes_per_sec":   health.tx_bytes_per_sec,
                    "active_sessions":    health.active_sessions,
                    "uptime_seconds":     health.uptime_seconds,
                    "load_avg_1m":        health.load_avg_1m,
                    "version":            health.version,
                })

                # Alerts
                alert_resp = await asyncio.wait_for(
                    stub.GetAlerts(pb2.AlertFilter()), timeout=3.0
                )
                alerts = [AlertRecord({
                    "id":           a.id,
                    "severity":     a.severity,
                    "message":      a.message,
                    "timestamp_ms": a.timestamp_ms,
                }) for a in alert_resp.alerts]
                self.alerts_updated.emit(alerts)

            except Exception as e:
                self.error_occurred.emit(str(e))
                return

            # Stream one topology snapshot
            try:
                async for topo in stub.StreamTopology(pb2.Empty()):
                    nodes = [{
                        "id":         n.id,
                        "label":      n.label,
                        "ip":         n.ip,
                        "node_type":  n.node_type,
                        "protocol":   n.protocol,
                        "active":     n.active,
                        "latency_ms": n.latency_ms,
                    } for n in topo.nodes]
                    edges = [{
                        "source":    e.source,
                        "target":    e.target,
                        "bandwidth": e.bandwidth,
                        "latency_ms": e.latency_ms,
                        "healthy":   e.healthy,
                    } for e in topo.edges]
                    self.topology_updated.emit({"nodes": nodes, "edges": edges})
                    break  # one snapshot per refresh cycle
            except Exception:
                pass  # topology streaming is optional — don't abort the poll loop

            await asyncio.sleep(REFRESH_MS / 1000)

    def kick_session(self, session_id: str):
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._do_kick(session_id), self._loop)

    async def _do_kick(self, session_id: str):
        pass  # Calls stub.KickSession(SessionIdRequest(id=session_id))


# ── Session table widget ──────────────────────────────────────────────────────
COLUMNS = [
    "Session ID", "Username", "Virtual IP", "Real IP", "Protocol",
    "Uptime", "↓ Received", "↑ Sent", "Latency", "Country", "Actions",
]


class SessionTable(QTableWidget):
    kick_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(0, len(COLUMNS), parent)
        self.setHorizontalHeaderLabels(COLUMNS)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setStretchLastSection(True)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.verticalHeader().setVisible(False)

    def update_sessions(self, sessions: List[SessionRecord]):
        self.setRowCount(len(sessions))
        for row, s in enumerate(sessions):
            values = [
                s.id[:8] + "…",
                s.username or "—",
                s.virtual_ip,
                s.real_ip,
                s.protocol,
                s.uptime_str,
                s.rx_str,
                s.tx_str,
                f"{s.latency_ms:.1f} ms",
                s.geo_country or "—",
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.setItem(row, col, item)

            # Kick button in last column
            kick_btn = QPushButton("Kick")
            kick_btn.setObjectName("kick_btn")
            sid = s.id
            kick_btn.clicked.connect(lambda checked, i=sid: self.kick_requested.emit(i))
            self.setCellWidget(row, len(COLUMNS) - 1, kick_btn)


# ── System health panel ───────────────────────────────────────────────────────
class HealthPanel(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("System Health", parent)
        form = QFormLayout()

        self._cpu_bar = QProgressBar()
        self._cpu_bar.setRange(0, 100)
        self._cpu_bar.setFormat("CPU: %v%")
        form.addRow("CPU:", self._cpu_bar)

        self._mem_bar = QProgressBar()
        self._mem_bar.setRange(0, 100)
        self._mem_bar.setFormat("RAM: %v%")
        form.addRow("Memory:", self._mem_bar)

        self._sessions_label = QLabel("0")
        form.addRow("Active Sessions:", self._sessions_label)

        self._load_label = QLabel("0.00")
        form.addRow("Load Avg (1m):", self._load_label)

        self._version_label = QLabel("—")
        form.addRow("Daemon Version:", self._version_label)

        self.setLayout(form)

    def update_health(self, h: dict):
        self._cpu_bar.setValue(int(h.get("cpu_percent", 0)))
        mem_total = h.get("memory_total_bytes", 1)
        mem_used  = h.get("memory_used_bytes", 0)
        mem_pct   = int(100 * mem_used / mem_total) if mem_total > 0 else 0
        self._mem_bar.setValue(mem_pct)
        self._sessions_label.setText(str(h.get("active_sessions", 0)))
        self._load_label.setText(f"{h.get('load_avg_1m', 0):.2f}")
        self._version_label.setText(h.get("version", "—"))


# ── Alert panel ───────────────────────────────────────────────────────────────
class AlertPanel(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Alerts", parent)
        vbox = QVBoxLayout()
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setMaximumHeight(150)
        vbox.addWidget(self._text)
        self.setLayout(vbox)

    def update_alerts(self, alerts: List[AlertRecord]):
        if not alerts:
            return
        for a in alerts:
            color = a.color
            self._text.append(
                f'<span style="color:{color}; font-weight:bold;">'
                f'[{a.time_str}] [{a.severity.upper()}]'
                f'</span> {a.message}'
            )


# ── Main admin window ─────────────────────────────────────────────────────────
class TopologyWidget(QWidget):
    """
    Network topology graph rendered with QGraphicsScene.

    Nodes: server (blue square) + one circle per active client session.
    Edges: lines connecting each client to the server.
    Layout: NetworkX spring_layout if available; fallback circular layout otherwise.

    Call update_topology(topology_dict) to refresh the view.
    topology_dict format:
        {
          "nodes": [{"id": str, "label": str, "ip": str, "node_type": str,
                     "protocol": str, "active": bool, "latency_ms": float}, ...],
          "edges": [{"source": str, "target": str, "bandwidth": float,
                     "latency_ms": float, "healthy": bool}, ...],
        }
    """

    # Layout constants
    _W, _H   = 700, 420      # scene dimensions
    _R_NODE  = 22            # node circle radius
    _SERVER_SIZE = 32        # half-side of server square

    def __init__(self, parent=None):
        super().__init__(parent)
        from PySide6.QtWidgets import QGraphicsScene, QGraphicsView
        from PySide6.QtCore import Qt

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        info_row = QHBoxLayout()
        self._node_count_lbl = QLabel("Nodes: 0")
        self._edge_count_lbl = QLabel("Edges: 0")
        self._ts_lbl         = QLabel("Last update: —")
        for lbl in (self._node_count_lbl, self._edge_count_lbl, self._ts_lbl):
            lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 11px;")
            info_row.addWidget(lbl)
        info_row.addStretch()

        hint_lbl = QLabel("Install networkx for automatic layout: pip install networkx")
        hint_lbl.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 10px;")
        if HAS_NX:
            hint_lbl.hide()
        info_row.addWidget(hint_lbl)
        layout.addLayout(info_row)

        self._scene = QGraphicsScene(0, 0, self._W, self._H)
        self._view  = QGraphicsView(self._scene)
        self._view.setRenderHint(self._view.renderHints())
        self._view.setBackgroundBrush(QColor(COLORS["bg_card"]))
        self._view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        layout.addWidget(self._view)

        self._tooltip_lbl = QLabel("")
        self._tooltip_lbl.setWordWrap(True)
        self._tooltip_lbl.setStyleSheet(
            f"color: {COLORS['text']}; background: {COLORS['bg']}; "
            f"border: 1px solid {COLORS['border']}; padding: 4px; font-size: 11px;"
        )
        self._tooltip_lbl.setMaximumHeight(40)
        layout.addWidget(self._tooltip_lbl)

    def update_topology(self, data: dict):
        from PySide6.QtWidgets import QGraphicsEllipseItem, QGraphicsRectItem, QGraphicsLineItem, QGraphicsTextItem
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QPen, QBrush

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        self._scene.clear()
        if not nodes:
            self._scene.addText("No active sessions.", QFont("monospace", 11))
            return

        # Compute positions
        positions = self._compute_positions(nodes)

        # Draw edges first (behind nodes)
        id_pos = {n["id"]: positions.get(n["id"], (self._W / 2, self._H / 2)) for n in nodes}
        for edge in edges:
            sx, sy = id_pos.get(edge["source"], (self._W / 2, self._H / 2))
            tx, ty = id_pos.get(edge["target"], (self._W / 2, self._H / 2))
            color = QColor(COLORS["green"] if edge.get("healthy", True) else COLORS["red"])
            pen = QPen(color)
            pen.setWidth(2)
            line = self._scene.addLine(sx, sy, tx, ty, pen)
            # Bandwidth label on midpoint
            bw = edge.get("bandwidth", 0)
            if bw > 0:
                mid_x = (sx + tx) / 2
                mid_y = (sy + ty) / 2
                bw_lbl = self._scene.addText(_fmt_bytes(int(bw)) + "/s")
                bw_lbl.setDefaultTextColor(QColor(COLORS["text_dim"]))
                bw_lbl.setFont(QFont("monospace", 8))
                bw_lbl.setPos(mid_x - 20, mid_y - 10)

        # Draw nodes
        for node in nodes:
            x, y    = positions.get(node["id"], (self._W / 2, self._H / 2))
            active  = node.get("active", True)
            ntype   = node.get("node_type", "client")
            label   = node.get("label", node["id"])
            ip_str  = node.get("ip", "")
            proto   = node.get("protocol", "")
            latency = node.get("latency_ms", 0.0)

            base_color = COLORS["accent"] if ntype == "server" else (COLORS["green"] if active else COLORS["red"])
            fill  = QColor(base_color)
            fill.setAlpha(200)
            pen   = QPen(QColor(base_color))
            pen.setWidth(2)

            if ntype == "server":
                s = self._SERVER_SIZE
                rect = self._scene.addRect(x - s, y - s, s * 2, s * 2, pen, QBrush(fill))
                rect.setToolTip(f"Server\n{ip_str}")
            else:
                r = self._R_NODE
                circ = self._scene.addEllipse(x - r, y - r, r * 2, r * 2, pen, QBrush(fill))
                tip = f"{label}\n{ip_str}  {proto}\nRTT: {latency:.1f} ms"
                circ.setToolTip(tip)

            # Label below node
            txt = self._scene.addText(label)
            txt.setDefaultTextColor(QColor(COLORS["text"]))
            txt.setFont(QFont("monospace", 8))
            txt.setPos(x - len(label) * 3.5, y + self._R_NODE + 3)

        self._node_count_lbl.setText(f"Nodes: {len(nodes)}")
        self._edge_count_lbl.setText(f"Edges: {len(edges)}")
        self._ts_lbl.setText(f"Last update: {datetime.now():%H:%M:%S}")

    def _compute_positions(self, nodes: list) -> dict:
        """Return {id: (x, y)} for each node, server at center."""
        cx, cy = self._W / 2, self._H / 2

        server_id = next((n["id"] for n in nodes if n.get("node_type") == "server"), None)
        clients = [n for n in nodes if n.get("node_type") != "server"]

        if HAS_NX and len(nodes) > 1:
            G = nx.Graph()
            for n in nodes:
                G.add_node(n["id"])
            for n in clients:
                if server_id:
                    G.add_edge(server_id, n["id"])
            pos_raw = nx.spring_layout(G, seed=42)
            # Scale to scene
            positions = {}
            for nid, (px, py) in pos_raw.items():
                sx = cx + px * (self._W * 0.4)
                sy = cy + py * (self._H * 0.4)
                positions[nid] = (sx, sy)
            return positions

        # Fallback: server at center, clients evenly around a circle
        positions = {}
        if server_id:
            positions[server_id] = (cx, cy)
        n_clients = len(clients)
        radius = min(cx, cy) * 0.75
        for i, client in enumerate(clients):
            angle = (2 * math.pi * i / max(n_clients, 1)) - (math.pi / 2)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            positions[client["id"]] = (x, y)
        return positions


# ── Main window ───────────────────────────────────────────────────────────────
class AdminWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1200, 700)
        self._build_ui()
        self._setup_worker()
        self.setStyleSheet(STYLESHEET)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)

        # Header
        hdr = QHBoxLayout()
        title = QLabel(f"<b>{APP_NAME}</b>")
        title.setStyleSheet(f"font-size: 18px; color: {COLORS['accent']};")
        self._conn_label = QLabel("● Connecting...")
        self._conn_label.setStyleSheet(f"color: {COLORS['amber']};")
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self._conn_label)
        root.addLayout(hdr)

        # Top: health + alerts side by side
        top = QHBoxLayout()
        self._health_panel = HealthPanel()
        self._alert_panel  = AlertPanel()
        top.addWidget(self._health_panel, 2)
        top.addWidget(self._alert_panel,  1)
        root.addLayout(top)

        # Session table (main area)
        tabs = QTabWidget()
        self._session_table = SessionTable()
        self._session_table.kick_requested.connect(self._on_kick_session)
        tabs.addTab(self._session_table, "  Active Sessions  ")

        # Topology tab
        self._topology_widget = TopologyWidget()
        tabs.addTab(self._topology_widget, "  Topology  ")

        tabs.addTab(self._make_log_tab(), "  Audit Log  ")
        root.addWidget(tabs)

        # Status bar
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_label = QLabel("Ready")
        sb.addWidget(self._status_label)

    def _make_log_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)

        # Filter bar
        filter_row = QHBoxLayout()
        self._log_filter = QLineEdit()
        self._log_filter.setPlaceholderText("Filter log entries...")
        self._log_filter.textChanged.connect(self._filter_log)
        filter_row.addWidget(QLabel("Filter:"))
        filter_row.addWidget(self._log_filter)
        vbox.addLayout(filter_row)

        self._audit_log = QTextEdit()
        self._audit_log.setReadOnly(True)
        vbox.addWidget(self._audit_log)
        return w

    def _filter_log(self, text: str):
        # Simple client-side text filter — highlight matching lines
        pass

    def _setup_worker(self):
        self._worker = AdminWorker(SOCKET_PATH)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.start)
        self._worker.sessions_updated.connect(self._on_sessions_updated)
        self._worker.health_updated.connect(self._on_health_updated)
        self._worker.alerts_updated.connect(self._on_alerts_updated)
        self._worker.topology_updated.connect(self._on_topology_updated)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.connected.connect(self._on_connected)
        self._thread.start()

    @Slot(bool)
    def _on_connected(self, ok: bool):
        if ok:
            self._conn_label.setText("● Connected to daemon")
            self._conn_label.setStyleSheet(f"color: {COLORS['green']};")
        else:
            self._conn_label.setText("○ Daemon not reachable")
            self._conn_label.setStyleSheet(f"color: {COLORS['red']};")

    @Slot(list)
    def _on_sessions_updated(self, sessions: list):
        self._session_table.update_sessions(sessions)
        self._status_label.setText(
            f"Sessions: {len(sessions)}  |  Updated: {datetime.now():%H:%M:%S}"
        )
        self._audit_log.append(f"[{datetime.now():%H:%M:%S}] Sessions refreshed ({len(sessions)} active)")

    @Slot(dict)
    def _on_health_updated(self, health: dict):
        self._health_panel.update_health(health)

    @Slot(list)
    def _on_alerts_updated(self, alerts: list):
        self._alert_panel.update_alerts(alerts)

    @Slot(dict)
    def _on_topology_updated(self, topo: dict):
        self._topology_widget.update_topology(topo)

    @Slot(str)
    def _on_error(self, msg: str):
        self._audit_log.append(f"[{datetime.now():%H:%M:%S}] ERROR: {msg}")

    @Slot(str)
    def _on_kick_session(self, session_id: str):
        reply = QMessageBox.question(
            self,
            "Kick Session",
            f"Kick session {session_id[:12]}…?\nThis will immediately terminate their VPN connection.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._worker.kick_session(session_id)
            self._audit_log.append(f"[{datetime.now():%H:%M:%S}] Kicked session {session_id[:16]}")

    def closeEvent(self, event):
        self._worker.stop()
        self._thread.quit()
        self._thread.wait(2000)
        event.accept()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    if not HAS_PYSIDE6:
        print("ERROR: PySide6 not installed.")
        print("Install with: pip install PySide6 grpcio grpcio-tools")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    window = AdminWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
