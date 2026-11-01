"""The window a Ghost session opens with: what this session is, in four lights.

Shown on every Ghost login (the session has no memory, so it cannot know it
was shown before). A status board rather than a page: each line is a light —
solid when it holds, hollow while it is still being checked, marked when it
needs attention — and the Tor light keeps checking until Tor is carrying
traffic, through the same path every program in the session has to take.
"""
from __future__ import annotations

import shutil
import subprocess
import time

from PyQt6.QtCore import QRectF, QTimer, Qt
from PyQt6.QtGui import QColor, QPainter, QPen
from PyQt6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QMainWindow, QVBoxLayout,
                             QWidget)

from mazeghost import status
from mazeghost.gui import worker
from mazeghost.gui.chrome import TitleBar, WindowButton, button, label
from mazeghost.gui.glass import GlassBackground, GlassFrame
from mazeghost.gui.i18n import t
from mazeghost.gui.icons import app_logo, logo_pixmap

TOR_RETRY_MS = 4000
TOR_SLOW_AFTER = 90.0


class Light(QWidget):
    """ok: solid · wait: hollow, breathing · warn: hollow with a bar."""

    def __init__(self, state: str = "wait"):
        super().__init__()
        self.state = state
        self.phase = 0.0
        self.setFixedSize(22, 22)
        self._tick = QTimer(self, interval=60)
        self._tick.timeout.connect(self._breathe)
        self._tick.start()

    def set_state(self, state: str) -> None:
        self.state = state
        self.update()

    def _breathe(self) -> None:
        if self.state == "wait":
            self.phase = (self.phase + 0.06) % 2.0
            self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(3, 3, 16, 16)
        if self.state == "ok":
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor("#f2f2f4"))
            p.drawEllipse(r)
        else:
            alpha = 255 if self.state == "warn" else int(110 + 120 * abs(1.0 - self.phase))
            p.setPen(QPen(QColor(242, 242, 244, alpha), 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(r)
            if self.state == "warn":
                p.drawLine(11, 7, 11, 12)
                p.drawPoint(11, 15)
        p.end()


class StatusRow(QWidget):
    def __init__(self, state: str, title: str, desc: str):
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 8, 0, 8)
        h.setSpacing(14)
        self.light = Light(state)
        h.addWidget(self.light, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(2)
        self.title = label(title, "title", wrap=True)
        self.desc = label(desc, "hint", wrap=True)
        col.addWidget(self.title)
        col.addWidget(self.desc)
        h.addLayout(col, 1)

    def set(self, state: str, title: str, desc: str) -> None:
        self.light.set_state(state)
        self.title.setText(title)
        self.desc.setText(desc)


class WelcomeWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Maze Ghost")
        self.setWindowIcon(app_logo())
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.resize(580, 640)
        self._started = time.time()
        self._checking = False

        root = GlassBackground()
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        header = TitleBar(self)
        header.setFixedHeight(44)
        h = QHBoxLayout(header)
        h.setContentsMargins(16, 0, 0, 0)
        h.addWidget(label("MAZE GHOST", "wordmark"))
        h.addStretch(1)
        mn = WindowButton("win_min", t("tip_minimize"))
        mn.clicked.connect(self.showMinimized)
        cl = WindowButton("win_close", t("tip_close"))
        cl.clicked.connect(self.close)
        h.addWidget(mn)
        h.addWidget(cl)
        v.addWidget(header)

        body = QVBoxLayout()
        body.setContentsMargins(34, 26, 34, 26)
        body.setSpacing(6)
        mark = QLabel()
        mark.setPixmap(logo_pixmap(72))
        body.addWidget(mark)
        body.addSpacing(8)
        body.addWidget(label(t("eyebrow"), "eyebrow"))
        body.addWidget(label(t("title"), "h2", wrap=True))
        body.addWidget(label(t("sub"), "h2_sub", wrap=True))
        body.addSpacing(14)

        board = GlassFrame(radius=18, strength=1.15)
        bv = QVBoxLayout(board)
        bv.setContentsMargins(22, 12, 22, 12)
        bv.setSpacing(0)
        self.tor_row = StatusRow("wait", t("tor_wait"), t("tor_wait_d"))
        bv.addWidget(self.tor_row)
        bv.addWidget(StatusRow("ok", t("mem"), t("mem_d")))
        swaps = status.disk_swap()
        if swaps:
            bv.addWidget(StatusRow("warn", t("swap", dev=", ".join(swaps)), t("swap_d")))
        bv.addWidget(StatusRow("ok", t("keep"), t("keep_d")))
        body.addWidget(board)
        body.addStretch(1)

        row = QHBoxLayout()
        row.setSpacing(10)
        cap = button(t("btn_capsule"), "secondary_lg", "capsule")
        cap.clicked.connect(self.open_capsule)
        cap.setVisible(shutil.which("maze-capsule") is not None)
        row.addWidget(cap)
        row.addStretch(1)
        ok = button(t("btn_ok"), "get_lg")
        ok.clicked.connect(self.close)
        row.addWidget(ok)
        body.addLayout(row)
        v.addLayout(body, 1)
        self.setCentralWidget(root)

        self._timer = QTimer(self, interval=TOR_RETRY_MS)
        self._timer.timeout.connect(self.check_tor)
        self._timer.start()
        QTimer.singleShot(300, self.check_tor)

    def check_tor(self) -> None:
        if self._checking:
            return
        self._checking = True

        def done(res: tuple[bool, str]) -> None:
            self._checking = False
            ok, ip = res
            if ok:
                self._timer.stop()
                self.tor_row.set("ok", t("tor_ok"), t("tor_ok_d", ip=ip))
            elif time.time() - self._started > TOR_SLOW_AFTER:
                self.tor_row.set("warn", t("tor_slow"), t("tor_slow_d"))
        worker.run(status.tor_check, on_done=done,
                   on_fail=lambda _e: setattr(self, "_checking", False), critical=False)

    def open_capsule(self) -> None:
        subprocess.Popen(["maze-capsule"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)


def run() -> int:
    import sys
    from mazeghost.gui.theme import stylesheet
    app = QApplication(sys.argv)
    app.setApplicationName("Maze Ghost")
    app.setDesktopFileName("maze-ghost")
    app.setWindowIcon(app_logo())
    app.setStyleSheet(stylesheet())
    w = WelcomeWindow()
    w.show()
    code = app.exec()
    from PyQt6.QtCore import QThreadPool
    QThreadPool.globalInstance().waitForDone(3000)
    return code
