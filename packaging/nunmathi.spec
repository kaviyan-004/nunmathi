# PyInstaller spec for the Nunmathi desktop application (Linux and Windows). Run from the repository root:
#   pyinstaller --noconfirm --distpath build/dist --workpath build/work packaging/nunmathi.spec
# The UI is the single-file build in frontend/dist-app (npm run build:app), shown in a native window:
# Qt WebEngine (PySide6) on Linux, Microsoft Edge WebView2 on Windows. No web server is included or started.
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

ROOT = os.path.abspath(os.getcwd())
BACKEND = os.path.join(ROOT, "backend")
MODEL = os.environ.get("NUNMATHI_MODEL") or os.path.join(ROOT, "build", "model", "traffic.pkl")
WIN = os.name == "nt"

APP_UI = os.path.join(ROOT, "frontend", "dist-app")
if not os.path.exists(os.path.join(APP_UI, "index.html")):
    raise SystemExit("frontend/dist-app/index.html missing: run `npm run build:app` in frontend/ first")

datas = [(APP_UI, "frontend_app")]
if os.path.exists(MODEL):
    datas.append((MODEL, os.path.join("nunmathi", "models")))
datas += collect_data_files("reportlab") + collect_data_files("webview")

hidden = (collect_submodules("nunmathi") + collect_submodules("sklearn.ensemble")
          + ["sklearn.utils._typedefs", "sklearn.neighbors._partition_nodes", "yaml", "jsonschema", "webview"])
excludes = ["tkinter", "matplotlib", "pytest", "IPython", "pandas", "PyQt5", "PyQt6", "gi", "cefpython3"]
if WIN:
    hidden += ["webview.platforms.edgechromium", "webview.platforms.winforms", "clr", "clr_loader"]
    excludes += ["PySide6", "qtpy", "shiboken6"]
else:
    hidden += ["webview.platforms.qt", "qtpy", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineCore",
               "PySide6.QtWebChannel", "PySide6.QtNetwork", "PySide6.QtPrintSupport"]
    # only QtWebEngineWidgets is used; the QML/Quick hooks would pull in every QML plugin (3D, charts, multimedia...)
    excludes += ["PySide6." + m for m in ("QtQuick", "QtQuickWidgets", "QtQml", "QtPositioning", "QtDataVisualization",
                                          "QtOpenGLWidgets", "QtDBus", "QtMultimedia", "QtCharts", "Qt3DCore", "QtPdf",
                                          "QtQuick3D", "QtGraphs", "QtLocation", "QtSql", "QtTest", "QtSvg")]
    excludes += ["clr", "clr_loader", "pythonnet", "webview.platforms.edgechromium", "webview.platforms.winforms",
                 "webview.platforms.gtk", "webview.platforms.cocoa", "webview.platforms.android"]

a = Analysis([os.path.join(BACKEND, "nunmathi", "desktop.py")], pathex=[BACKEND], datas=datas,
             hiddenimports=hidden, excludes=excludes)
if not WIN:
    # Qt translations: keep English only (the UI is English); Chromium locales: keep en-US
    def _keep(dest):
        d = dest.replace("\\", "/")
        if "/Qt/translations/" in d:
            return "qtwebengine_locales/en-US" in d or d.endswith("_en.qm")
        return True
    a.datas = [x for x in a.datas if _keep(x[0])]
    # graphics stack comes from the system (it must match the installed Mesa/GPU drivers): the .deb depends on it
    _SYSTEM = ("libgbm.so", "libdrm.so", "libGL.so", "libEGL.so", "libGLX.so", "libGLdispatch.so", "libOpenGL.so",
               "libwayland-")
    a.binaries = [x for x in a.binaries if not os.path.basename(x[0]).startswith(_SYSTEM)]
pyz = PYZ(a.pure)

if WIN:
    icon = os.path.join(ROOT, "packaging", "nunmathi.ico")
    # Nunmathi.exe: the desktop application (GUI subsystem, never opens a console window)
    gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Nunmathi", console=False, icon=icon)
    # nunmathi-cli.exe: the same engine for scripts and CI (analyze, testbed, verify, schema ...)
    cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="nunmathi-cli", console=True, icon=icon)
    coll = COLLECT(gui, cli, a.binaries, a.datas, name="nunmathi")
else:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="nunmathi", console=True)
    coll = COLLECT(exe, a.binaries, a.datas, name="nunmathi")
