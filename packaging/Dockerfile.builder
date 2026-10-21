FROM python:3.12-slim-bookworm
# binutils for PyInstaller; the X11/GL/NSS libraries Qt WebEngine links against (so PyInstaller can resolve them
# and the GUI can be smoke-tested under Xvfb); xvfb + xauth + x11-apps for that test
RUN apt-get update && apt-get install -y --no-install-recommends binutils \
      libgl1 libegl1 libopengl0 libglib2.0-0 libfontconfig1 libfreetype6 libdbus-1-3 libnss3 libnspr4 libasound2 \
      libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
      libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxcb-xfixes0 libxcomposite1 libxdamage1 \
      libxrandr2 libxtst6 libxshmfence1 libxkbfile1 libx11-xcb1 libxi6 libxrender1 libxext6 libdrm2 libgbm1 \
      xvfb xauth x11-apps \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "pydantic>=2.7" "numpy>=2.0" "scikit-learn>=1.5" \
    "reportlab>=4.0" "PyYAML>=6.0" "jsonschema>=4.18" "pyinstaller>=6.10" \
    "pywebview>=5.3" "qtpy>=2.4" "PySide6>=6.7"
