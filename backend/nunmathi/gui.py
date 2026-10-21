"""Standalone desktop application: the Nunmathi UI in a native window, with no browser and no network port.

The window renders the bundled single-file UI with the operating system's web engine (WebView2 on Windows,
Qt WebEngine on Linux) purely as a drawing surface. The UI never talks HTTP: every API call goes through the
pywebview JavaScript bridge into :class:`Bridge`, which invokes the FastAPI application in-process as an ASGI
callable on a private event loop. Nothing listens on a socket.

Native services the page cannot do by itself (file open/save dialogs, opening a saved report with the system's
default viewer, external reference links) are also bridge methods.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import pathlib
import subprocess
import sys
import threading
import urllib.parse
import webbrowser

APP_TITLE = "Nunmathi"
TEXT_TYPES = ("application/json", "application/schema+json", "text/", "application/yaml")


class _Asgi:
    """Calls an ASGI app directly, on one private event loop, the way an HTTP server would - minus the socket."""

    def __init__(self, app):
        self.app = app
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, name="nunmathi-asgi", daemon=True)
        self._thread.start()
        self._lifespan_done: asyncio.Queue | None = None
        self._run(self._startup())

    def _run(self, coro, timeout: float | None = None):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    async def _startup(self) -> None:
        recv: asyncio.Queue = asyncio.Queue()
        started = self.loop.create_future()
        self._lifespan_in = recv
        self._lifespan_done = asyncio.Queue()

        async def receive():
            return await recv.get()

        async def send(msg):
            t = msg["type"]
            if t in ("lifespan.startup.complete", "lifespan.startup.failed") and not started.done():
                started.set_result(msg)
            elif t.startswith("lifespan.shutdown"):
                await self._lifespan_done.put(msg)

        self._lifespan_task = self.loop.create_task(
            self.app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send))
        await recv.put({"type": "lifespan.startup"})
        msg = await started
        if msg["type"] == "lifespan.startup.failed":
            raise RuntimeError(msg.get("message", "application startup failed"))

    async def _shutdown(self) -> None:
        await self._lifespan_in.put({"type": "lifespan.shutdown"})
        try:
            await asyncio.wait_for(self._lifespan_done.get(), 15)
        except asyncio.TimeoutError:
            pass

    def close(self) -> None:
        try:
            self._run(self._shutdown(), 20)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)

    def request(self, method: str, target: str, body: bytes = b"", headers: dict | None = None):
        return self._run(self._request(method, target, body, headers or {}))

    async def _request(self, method: str, target: str, body: bytes, headers: dict):
        u = urllib.parse.urlsplit(target)
        hdrs = [(k.lower().encode("latin-1"), str(v).encode("latin-1")) for k, v in headers.items()]
        hdrs.append((b"content-length", str(len(body)).encode()))
        hdrs.append((b"host", b"nunmathi.app"))
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method.upper(),
            "scheme": "http", "path": urllib.parse.unquote(u.path), "raw_path": u.path.encode(),
            "query_string": u.query.encode(), "root_path": "", "headers": hdrs,
            "client": ("127.0.0.1", 0), "server": ("nunmathi.app", 80), "state": {},
        }
        sent = False
        finished = asyncio.Event()

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await finished.wait()            # nothing more to read; the "client" leaves once the response is complete
            return {"type": "http.disconnect"}

        status = 500
        out_headers: dict[str, str] = {}
        chunks: list[bytes] = []

        async def send(msg):
            nonlocal status
            if msg["type"] == "http.response.start":
                status = msg["status"]
                for k, v in msg.get("headers", []):
                    out_headers[k.decode("latin-1").lower()] = v.decode("latin-1")
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    finished.set()

        try:
            await self.app(scope, receive, send)
        finally:
            finished.set()
        return status, out_headers, b"".join(chunks)


def _open_with_system(path: str) -> None:
    """Open a saved file with the default application of the desktop (PDF viewer, text editor...)."""
    try:
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


class Bridge:
    """Methods exposed to the UI as window.pywebview.api.* (each call runs on its own thread)."""

    def __init__(self, asgi: _Asgi):
        self._asgi = asgi
        self._window = None

    def attach(self, window) -> None:
        self._window = window

    # -- API transport -------------------------------------------------------------------------------------------
    def request(self, method: str, path: str, body: str | None = None, body_b64: str | None = None,
                content_type: str | None = None) -> dict:
        if not path.startswith("/api/"):
            return {"status": 404, "headers": {}, "text": json.dumps({"detail": "not found"})}
        raw = base64.b64decode(body_b64) if body_b64 else (body or "").encode()
        headers = {"content-type": content_type} if content_type else {}
        status, hdrs, data = self._asgi.request(method, path, raw, headers)
        return self._pack(status, hdrs, data)

    @staticmethod
    def _pack(status: int, hdrs: dict, data: bytes) -> dict:
        ctype = hdrs.get("content-type", "")
        if any(ctype.startswith(t) for t in TEXT_TYPES) or not data:
            return {"status": status, "headers": hdrs, "text": data.decode("utf-8", "replace")}
        return {"status": status, "headers": hdrs, "b64": base64.b64encode(data).decode()}

    # -- native file dialogs ---------------------------------------------------------------------------------
    def _dialog(self, kind, **kw):
        if self._window is None:
            return None
        return self._window.create_file_dialog(kind, **kw)

    def open_capture(self) -> dict | None:
        """Native "Open capture" dialog; the file is handed to the engine directly (no copy through the page)."""
        import webview
        sel = self._dialog(webview.OPEN_DIALOG, allow_multiple=False,
                           file_types=("Packet captures (*.pcap;*.pcapng;*.cap)", "All files (*.*)"))
        if not sel:
            return None
        path = sel[0] if isinstance(sel, (list, tuple)) else sel
        return self.analyze_path(path)

    def analyze_path(self, path: str) -> dict:
        with open(path, "rb") as fh:
            data = fh.read()
        q = urllib.parse.urlencode({"filename": os.path.basename(path)})
        status, hdrs, body = self._asgi.request("POST", f"/api/analyses?{q}", data,
                                                {"content-type": "application/octet-stream"})
        return self._pack(status, hdrs, body)

    def open_text(self) -> dict | None:
        """Native open dialog for a YAML testbed spec; returns its name and text."""
        import webview
        sel = self._dialog(webview.OPEN_DIALOG, allow_multiple=False,
                           file_types=("YAML testbed spec (*.yaml;*.yml)", "All files (*.*)"))
        if not sel:
            return None
        path = sel[0] if isinstance(sel, (list, tuple)) else sel
        with open(path, encoding="utf-8", errors="replace") as fh:
            return {"name": os.path.basename(path), "text": fh.read()}

    def save_download(self, path: str, suggested: str, open_after: bool = True) -> dict:
        """Fetch an API document (report, export, schema), ask where to save it, write it and open it."""
        import webview
        status, hdrs, data = self._asgi.request("GET", path)
        if status != 200:
            try:
                detail = json.loads(data).get("detail", "")
            except ValueError:
                detail = data[:200].decode("utf-8", "replace")
            return {"ok": False, "error": f"{status}: {detail}"}
        cd = hdrs.get("content-disposition", "")
        if "filename=" in cd:
            suggested = cd.split("filename=", 1)[1].strip().strip('"') or suggested
        ext = os.path.splitext(suggested)[1].lstrip(".").lower() or "bin"
        label = {"pdf": "PDF document", "json": "JSON document", "html": "HTML report", "yaml": "YAML"}.get(ext, ext)
        target = self._dialog(webview.SAVE_DIALOG, save_filename=suggested,
                              file_types=(f"{label} (*.{ext})", "All files (*.*)"))
        if not target:
            return {"ok": False, "cancelled": True}
        target = target[0] if isinstance(target, (list, tuple)) else target
        with open(target, "wb") as fh:
            fh.write(data)
        if open_after:
            _open_with_system(target)
        return {"ok": True, "path": target}

    def show_html(self, path: str, title: str) -> dict:
        """Render an HTML report in a second application window (not a browser)."""
        import webview
        status, _, data = self._asgi.request("GET", path)
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}"}
        webview.create_window(title, html=data.decode("utf-8", "replace"), width=1100, height=850)
        return {"ok": True}

    # -- misc ----------------------------------------------------------------------------------------------------
    def open_url(self, url: str) -> bool:
        """External references (RFCs, NIST, ATT&CK) open in the user's own browser; nothing else is allowed."""
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            return False
        webbrowser.open(url)
        return True

    def app_info(self) -> dict:
        from .analyzer import ENGINE_VERSION
        from . import store
        return {"engine": ENGINE_VERSION, "data_dir": store.DATA, "platform": sys.platform}


def _index_html() -> str:
    root = getattr(sys, "_MEIPASS", None)
    cands = []
    if root:
        cands.append(os.path.join(root, "frontend_app", "index.html"))
    here = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.join(here, "..", "..", "frontend", "dist-app", "index.html"))
    for c in cands:
        if os.path.exists(c):
            return os.path.abspath(c)
    raise FileNotFoundError("single-file UI not found; build it with: cd frontend && npm run build:app")


def selftest() -> int:
    """Exercise the bridge without a window (used by the build smoke tests and on headless machines)."""
    from .api import app
    asgi = _Asgi(app)
    b = Bridge(asgi)
    try:
        h = b.request("GET", "/api/health")
        assert h["status"] == 200, h
        a = json.loads(b.request("POST", "/api/analyses/demo/branch-office?sync=true")["text"])
        assert a["status"] == "done", a
        r = json.loads(b.request("GET", f"/api/analyses/{a['id']}/result")["text"])
        pdf = b.request("GET", f"/api/analyses/{a['id']}/report/executive.pdf")
        assert pdf["status"] == 200 and base64.b64decode(pdf["b64"])[:4] == b"%PDF", pdf.get("text")
        b.request("DELETE", f"/api/analyses/{a['id']}")
        _index_html()
        print(f"selftest ok: engine {json.loads(h['text'])['engine']}, demo grade {r['grade']['letter']}, "
              f"{len(r['tunnels'])} tunnel(s), executive PDF {len(base64.b64decode(pdf['b64']))} bytes")
        return 0
    finally:
        asgi.close()


def gl_probe() -> int:
    """Exit status 0 when Qt can create a working OpenGL context (run in a child process: Qt aborts otherwise)."""
    os.environ["QT_API"] = "pyside6"
    from PySide6.QtGui import QGuiApplication, QOffscreenSurface, QOpenGLContext

    _app = QGuiApplication(["nunmathi"])
    ctx = QOpenGLContext()
    if not ctx.create():
        return 1
    surface = QOffscreenSurface()
    surface.create()
    return 0 if ctx.makeCurrent(surface) else 1


def _needs_software_rendering() -> bool:
    """True when OpenGL is unusable (VMs, remote X, missing Mesa drivers); NUNMATHI_SOFTWARE_RENDER=1/0 overrides."""
    forced = os.environ.get("NUNMATHI_SOFTWARE_RENDER")
    if forced in ("0", "1"):
        return forced == "1"
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--gl-probe"]
    else:
        cmd = [sys.executable, "-m", "nunmathi.gui", "--gl-probe"]
    try:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=20).returncode != 0
    except (OSError, subprocess.TimeoutExpired):
        return True


WEBVIEW2_DOWNLOAD = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"


def _webview2_installed() -> bool:
    """Microsoft Edge WebView2 Runtime (any channel), found the same way pywebview looks for it."""
    import winreg

    channels = ("{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}",
                "{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}", "{65C35B14-6C1D-4122-AC46-7148CC9D6497}")
    for hive, prefix in ((winreg.HKEY_CURRENT_USER, "SOFTWARE"), (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node"),
                         (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE")):
        for key in channels:
            try:
                with winreg.OpenKey(hive, rf"{prefix}\Microsoft\EdgeUpdate\Clients\{key}") as k:
                    pv = str(winreg.QueryValueEx(k, "pv")[0])
            except OSError:
                continue
            major = pv.split(".")[0]
            if major.isdigit() and int(major) >= 86:
                return True
    return False


def message_box(text: str, title: str = APP_TITLE, flags: int = 0x10) -> int:
    """Native Windows message box (0x10 = error icon); returns the button pressed."""
    import ctypes

    return ctypes.windll.user32.MessageBoxW(None, text, title, flags)


def run(open_path: str | None = None, debug: bool = False) -> int:
    if os.name == "nt" and not _webview2_installed():
        # without it pywebview would fall back to Internet Explorer, which cannot run the Nunmathi UI
        answer = message_box("Nunmathi needs the Microsoft Edge WebView2 Runtime, which is not installed on this "
                             "computer. It is included with Windows 10 and 11 and is a free download from Microsoft."
                             "\n\nOpen the download page now?", flags=0x10 | 0x4)
        if answer == 6:  # IDYES
            webbrowser.open(WEBVIEW2_DOWNLOAD)
        return 3
    if os.name != "nt":
        # Linux uses the Qt WebEngine bundled with PySide6 (never a system PyQt5 that qtpy might find first)
        os.environ["QT_API"] = "pyside6"
        # no GPU sandbox surprises inside PyInstaller bundles / VMs
        os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu-compositing")
        if _needs_software_rendering():
            # Qt would abort with "Could not initialize GLX"; render the UI in software instead
            os.environ["QT_QUICK_BACKEND"] = "software"
            os.environ["QT_XCB_GL_INTEGRATION"] = "none"
            os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] += " --disable-gpu"
    import webview
    from .api import app

    asgi = _Asgi(app)
    bridge = Bridge(asgi)
    index = _index_html()
    icon = os.path.join(os.path.dirname(index), "nunmathi.png")
    # a file:// URI (not a bare path): pywebview would otherwise serve the folder over a local HTTP server
    window = webview.create_window(APP_TITLE, url=pathlib.Path(index).resolve().as_uri(), js_api=bridge, width=1440, height=920,
                                   min_size=(1024, 640), text_select=True)
    bridge.attach(window)

    if open_path:
        # "Open with Nunmathi" / double-clicked capture: analyze it as soon as the UI is up
        def _opened():
            try:
                res = bridge.analyze_path(open_path)
                # the UI registers its handler once React has mounted; wait for it if the analysis was quicker
                window.evaluate_js("(function f(r){window.__nunmathiOpened ? window.__nunmathiOpened(r)"
                                   f" : setTimeout(function(){{f(r)}}, 200)}})({json.dumps(res)})")
            except OSError as e:
                window.evaluate_js(f"alert({json.dumps(f'Cannot open {open_path}: {e}')})")
        window.events.loaded += lambda: threading.Thread(target=_opened, daemon=True).start()
    gui = "edgechromium" if os.name == "nt" else "qt"
    try:
        webview.start(gui=gui, debug=debug, http_server=False, private_mode=True,
                      icon=icon if os.path.exists(icon) else None)
    finally:
        asgi.close()
    return 0


if __name__ == "__main__" and sys.argv[1:] == ["--gl-probe"]:
    sys.exit(gl_probe())
