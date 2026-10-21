#!/bin/sh
# Packages build/dist/nunmathi (from build-linux-bundle.sh) into build/nunmathi_<ver>_amd64.deb
set -e
cd "$(dirname "$0")/.."
VER=$(cat packaging/VERSION)
P=packaging/deb
R=build/debroot
rm -rf "$R"
mkdir -p "$R/DEBIAN" "$R/opt" "$R/usr/bin" "$R/usr/share/applications" "$R/usr/share/doc/nunmathi" \
         "$R/usr/share/icons/hicolor/256x256/apps" "$R/usr/share/icons/hicolor/scalable/apps"
cp -a build/dist/nunmathi "$R/opt/nunmathi"
install -m 755 $P/wrapper "$R/usr/bin/nunmathi"
install -m 644 $P/nunmathi.desktop "$R/usr/share/applications/nunmathi.desktop"
install -m 644 packaging/nunmathi-256.png "$R/usr/share/icons/hicolor/256x256/apps/nunmathi.png"
install -m 644 packaging/nunmathi.svg "$R/usr/share/icons/hicolor/scalable/apps/nunmathi.svg"
install -m 644 README.md "$R/usr/share/doc/nunmathi/README.md"
[ -d docs ] && cp -r docs "$R/usr/share/doc/nunmathi/docs"
for s in preinst postinst prerm postrm; do install -m 755 $P/$s "$R/DEBIAN/$s"; done
SIZE=$(du -sk "$R" | cut -f1)
cat > "$R/DEBIAN/control" <<CTL
Package: nunmathi
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Depends: libc6 (>= 2.36), zlib1g, libgl1, libegl1, libopengl0, libglib2.0-0, libfontconfig1, libfreetype6,
 libdbus-1-3, libnss3, libnspr4, libasound2 | libasound2t64, libxkbcommon0, libxkbcommon-x11-0, libxcb-cursor0,
 libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0, libxcb-shape0,
 libxcb-xinerama0, libxcb-xkb1, libxcomposite1, libxdamage1, libxrandr2, libxtst6, libxshmfence1,
 libxkbfile1, libx11-xcb1, libxi6, libxrender1, libgbm1, libdrm2, libwayland-client0, libwayland-server0,
 libwayland-egl1 | libwayland-egl1-mesa, libwayland-cursor0
Recommends: xdg-utils, shared-mime-info
Suggests: wireshark-common | tcpdump
Conflicts: veilscope
Replaces: veilscope
Provides: veilscope
Installed-Size: $SIZE
Maintainer: Nunmathi maintainers <nunmathi@localhost>
Homepage: https://nunmathi.local
Description: Passive, AI-assisted IPsec VPN security analyzer
 Nunmathi analyzes pcap/pcapng captures or live SPAN/TAP traffic of IPsec
 VPNs (IKEv1/IKEv2/ESP). It reconstructs tunnels and IKE ladders, proves ESP
 cipher geometry from packet lengths, infers application traffic with
 conformal confidence and SHAP explanations, maps findings to MITRE ATT&CK
 and standards, and verifies hardening recommendations in a built-in testbed.
 Produces executive and technical PDF reports and versioned JSON for SIEM/SOAR.
 .
 A standalone desktop application (native window, no browser, no web server);
 "nunmathi analyze|testbed|verify|schema" provide the same engine for scripts and CI.
CTL
dpkg-deb --root-owner-group -Zxz --build "$R" "build/nunmathi_${VER}_amd64.deb"
