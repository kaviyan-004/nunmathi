#!/bin/sh
# Builds the PyInstaller onedir bundle inside a Debian bookworm container (glibc 2.36) so the result runs on
# Debian 12+, Ubuntu 22.04+ and newer. Output: build/dist/nunmathi/
set -e
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/src -w /src -e HOME=/tmp -u "$(id -u):$(id -g)" nunmathi-builder:bookworm sh -c '
  set -e
  python packaging/train_model.py
  pyinstaller --noconfirm --clean --distpath build/dist --workpath build/work packaging/nunmathi.spec
'
