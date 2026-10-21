#!/bin/sh
# Builds both installers from a source checkout. Needs: node/npm, docker, wine with Python 3.12 (x64) at
# C:\Python312 plus the packages in packaging/Dockerfile.builder, makensis, dpkg-deb.
#   build/nunmathi_<ver>_amd64.deb   build/Nunmathi-Setup-<ver>.exe
set -e
cd "$(dirname "$0")/.."
VER=$(cat packaging/VERSION)
# the desktop UI: one self-contained HTML file loaded from disk by the native window
(cd frontend && npm ci && npm run build:app)
# Linux: bundle inside Debian bookworm (glibc 2.36), then package
docker build -t nunmathi-builder:bookworm -f packaging/Dockerfile.builder packaging
packaging/build-linux-bundle.sh
packaging/build-deb.sh
# Windows: model and bundle built with the Windows Python under Wine, then NSIS
export WINEDEBUG=-all
WPY="$HOME/.wine/drive_c/Python312/python.exe"
wine "$WPY" packaging/train_model.py build/model-win/traffic.pkl
NUNMATHI_MODEL="$(winepath -w build/model-win/traffic.pkl)" \
  wine "$WPY" -m PyInstaller --noconfirm --clean --distpath build/dist-win --workpath build/work-win packaging/nunmathi.spec
makensis -V2 -DVERSION="$VER" packaging/nunmathi.nsi
ls -l build/*.deb build/*.exe
