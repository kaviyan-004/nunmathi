# Nunmathi — passive, AI-assisted IPsec VPN analyzer

Nunmathi reads a packet capture (pcap or pcapng) of IPsec traffic, or captures live from a network interface, and reports how well the VPN is protected.
It never decrypts anything. It works only from what is visible on the wire: IKE negotiation, ESP packet sizes and timing, and NAT-T and rekey behaviour.

For each tunnel it reports:

- **Negotiated cryptography** from IKEv1/IKEv2 decoding: proposals, chosen transforms, RFC 9370 additional key exchanges such as ML-KEM, identities, Vendor IDs and notifications.
- **ESP cipher geometry.** The ESP cipher and integrity algorithm are inferred from packet-length arithmetic (block size, IV and ICV length). It can tell AEAD, CBC+HMAC and ESP-NULL apart without keys.
- **PFS and lifetimes**, inferred from Child SA and IKE SA rekeys (SPI changes and CREATE_CHILD_SA exchanges).
- **Application traffic classes** that leak through the encryption: voip, video, web, chat and email. A gradient-boosting model classifies 5 s windows. It adds conformal prediction sets, out-of-distribution detection and a Metadata Exposure Index (MEI).
- **Alerts in the OWASP ZAP style.** Each has a rule ID, risk, confidence, evidence, solution and references, and together they produce an A+…F grade.
- **What-If digital twin.** It re-scores a tunnel with proposed changes applied and generates matching strongSwan and libreswan configuration.
- **Live mode.** A real-time packet stream from network hardware (via `dumpcap` or `tcpdump`) is analyzed while it arrives. New tunnels, rekeys, grade changes and alerts are reported as they happen, and the stream is also recorded to a pcap.

Nunmathi is a **standalone desktop application**. It opens in its own native window with its own menus and file dialogs. There is no browser, no URL bar, no console window and no network port: the interface talks to the analysis engine in-process.

The application follows the layout of the **OWASP ZAP desktop client**:

- A menu bar and toolbar.
- A *Sites*-style tree of captures, tunnels and SAs.
- A request/response-style workspace with tabs.
- Bottom panels for History, Alerts, Output and Analyses.

Nunmathi is not affiliated with OWASP; only the look is borrowed.

```
nunmathi/
├── backend/            Python engine, REST API, CLI, tests
│   ├── nunmathi/      pcap · ike · geometry · sessions · traffic · assess · analyzer · report · api · cli · forge/
│   ├── tests/          pytest suite (52 tests) + real strongSwan capture fixtures
│   └── requirements.txt
├── frontend/           React 19 + TypeScript + Vite (ZAP-style UI, built into one self-contained HTML file)
├── packaging/          PyInstaller spec, .deb and NSIS (Windows installer) build scripts
└── docs/               architecture, detection rules, ML model card
```

## Installers

Both packages are self-contained. They bundle the Python runtime, the application window, the UI and a pre-trained traffic model, so first start does not need to train.

| Platform | File | Requires |
|---|---|---|
| Debian 12+, Ubuntu 24.04+, Kali (amd64) | `nunmathi_1.2.0_amd64.deb` | glibc ≥ 2.36 and a graphical desktop (X11 or XWayland); apt installs the rest |
| Windows 10/11 x64 | `Nunmathi-Setup-1.2.0.exe` | Microsoft Edge WebView2 Runtime (part of Windows 10/11); live capture needs [Wireshark](https://www.wireshark.org/download.html) (dumpcap + Npcap) |

**Linux**

```bash
sudo apt install ./nunmathi_1.2.0_amd64.deb
```

- The package installs to `/opt/nunmathi` and puts `nunmathi` on the PATH.
- Start *Nunmathi* from the application menu, or run `nunmathi` with no arguments. `nunmathi capture.pcap` opens the window and analyzes that capture immediately. Captures also get *Open With → Nunmathi* in the file manager.
- The window is drawn with Qt WebEngine. On machines without working OpenGL (VMs, remote X) Nunmathi switches to software rendering by itself; `NUNMATHI_SOFTWARE_RENDER=1` forces it and `=0` disables the check.
- The data directory is `~/.local/share/nunmathi`.
- The product was called **VeilScope** up to 1.1.0. Installing Nunmathi removes the `veilscope` package (and the old 1.0.0 systemd service, if still present), and the first start moves `~/.local/share/veilscope` to `~/.local/share/nunmathi`.
- For live capture, install `tshark` or `tcpdump` and give the tool capture rights, for example with `sudo dpkg-reconfigure wireshark-common`.

**Windows**

- Run the setup program. It needs administrator rights and installs to `C:\Program Files\Nunmathi`.
- The *Nunmathi* Start-menu and desktop shortcuts open the application window (`Nunmathi.exe`). Captures get *Open with → Nunmathi*; Wireshark stays the default program for them.
- If the WebView2 Runtime is missing, both the installer and the application say so and offer Microsoft's download page.
- *Nunmathi command line* opens a prompt with `nunmathi-cli` on the PATH.
- Data lives in `%LOCALAPPDATA%\Nunmathi`. If the application ever stops unexpectedly, details are written to `crash.log` there.
- Uninstall from *Settings → Apps* or from the Start menu. The uninstaller asks whether to keep your data.
- Silent install and uninstall: `Nunmathi-Setup-1.2.0.exe /S` and `"C:\Program Files\Nunmathi\Uninstall.exe" /S`.

**Building the installers**

`packaging/build-all.sh` builds both installers. It needs:
- Node, to build the UI into a single HTML file (`npm run build:app`)
- Docker, used to build the Linux bundle (PySide6 / Qt WebEngine) on Debian bookworm for glibc portability
- Wine with a Windows Python 3.12 (x64), the packages from `packaging/Dockerfile.builder`, and `pywebview` + `pythonnet` in place of PySide6
- `makensis`
- `dpkg-deb`

## Running from source

Requirements: Python ≥ 3.11 (with `pywebview` and, on Linux, `PySide6`) and Node ≥ 20.

```bash
cd backend && pip install -r requirements.txt pywebview PySide6
```

```bash
cd frontend && npm install && npm run build:app
```

```bash
cd backend && python -m nunmathi gui
```

Use **File → Load demo: …**, **File → Open Capture…** (or drop a `.pcap`/`.pcapng` file on the Quick Start page), or open the **Live Capture** tab.

On first use from source the traffic model trains itself from synthetic data, which takes a few seconds. It is then cached under `backend/data/models/`.

For UI development only, the engine can also be served over HTTP on loopback and the UI run with Vite, which proxies `/api` to port 8750. This is not part of the installed product:

```bash
cd backend && python -m nunmathi serve
```

```bash
cd frontend && npm run dev
```

## CLI

The installed command is `nunmathi` on Linux and `nunmathi-cli` on Windows. From source, use `python -m nunmathi`.

```bash
cd backend && python -m nunmathi scenarios
```

```bash
cd backend && python -m nunmathi forge legacy-ikev1 /tmp/legacy.pcap --truth /tmp/legacy-truth.json
```

```bash
cd backend && python -m nunmathi analyze /tmp/legacy.pcap
```

```bash
cd backend && python -m nunmathi analyze /tmp/legacy.pcap -f pdf -o legacy-report.pdf
```

```bash
cd backend && python -m nunmathi analyze capture.pcapng --fail-on High
```

| Command | Purpose |
|---|---|
| `analyze CAPTURE [-f text\|json\|html\|pdf] [-o FILE] [--fail-on High\|Medium\|Low]` | Analyze a capture. `--fail-on` exits with status 2 when an alert of that risk or worse is present, which suits CI gates. |
| `forge SCENARIO OUTPUT [--truth FILE]` | Write a synthetic demo capture. `--truth` also writes the ground-truth JSON to FILE. |
| `scenarios` | List the demo scenarios. |
| `live -i IFACE [--filter BPF] [--backend dumpcap\|tcpdump] [-d SECONDS] [--max-packets N] [--interval S] [-f …] [-o FILE] [--fail-on …]` | Capture and analyze live. Ctrl-C stops and prints the report. `live --list` lists interfaces and capture tools; `live --replay FILE [--speed X]` streams a capture file through the same pipeline in real time. |
| `train` | Retrain the traffic model and print its model card. |
| `gui [CAPTURE]` | Open the desktop application, optionally analyzing CAPTURE right away. This is what the installed `nunmathi` does with no arguments. `--selftest` checks the engine and report generation without opening a window. |
| `testbed SPEC.yaml [-f …] [-o FILE]` | Build the VPN topology described in a YAML spec in IPsecForge, capture it and analyze it. |
| `verify CAPTURE [-t TUNNEL] [-c CHANGES] [--json]` | Apply the What-If recommendations to one tunnel in the testbed, re-capture, re-score and print the verified before/after comparison. |
| `schema` | Print the versioned JSON Schema of the JSON report, for SIEM/SOAR ingestion. |

`analyze -f executive` writes the 2–3 page executive PDF. `-f pdf` writes the 15–30 page technical PDF with audit log, rule citations, geometry proofs, evidence, and strongSwan, libreswan and Cisco IOS snippets.

### Demo scenarios (verified results)

| Scenario | What it contains | Grade |
|---|---|---|
| `hardened-pq` | IKEv2, AES-256-GCM, ECP-384 + ML-KEM-768, PFS, 1 h Child SA | A (94) |
| `branch-office` | IKEv2 AES-128-GCM / X25519, PFS, 12 h Child and 24 h IKE lifetimes | A (91) |
| `remote-access` | IKEv2 AES-CBC-128 / SHA-256 / MODP-2048 behind NAT, no PFS, weak algorithms also offered | B (81) |
| `legacy-ikev1` | IKEv1 Aggressive Mode with PSK, 3DES / SHA-1 / MODP-1024 | F (0) |
| `misconfigured-lab` | ESP-NULL, SHA-1, MODP-1536, half-open IKE flood | F (3) |

## Live mode

Live mode reads a real-time packet stream from a network interface. Nunmathi runs a capture tool that writes pcap to a pipe:

- `dumpcap -i IFACE -F pcap -w - -f FILTER`, preferred;
- or `tcpdump -i IFACE -U -w - FILTER`.

It then decodes frames as they arrive, keeps a copy of the stream on disk, and re-analyzes periodically. Differences between successive results become events: new tunnel, IKE/Child SA rekey, grade change and new alert. When the capture stops (Stop button, Ctrl-C, duration, packet or size limit, or the tool exiting), a final analysis is stored. It then behaves like any uploaded capture, with reports, What-If and History.

```bash
cd backend && python -m nunmathi live --list
```

```bash
cd backend && python -m nunmathi live -i eth0 -d 600 -f html -o live-report.html
```

**Privileges.** Capturing needs `CAP_NET_RAW`. The two usual ways to get it:

- Wireshark's `dumpcap` is normally installed with the capabilities for members of the `wireshark` group.
- For tcpdump, run as root or grant the capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump
```

The UI and `live --list` show which tools can capture. A failing tool's own error message is shown as is.

The default kernel filter is `udp port 500 or udp port 4500 or esp or ah`.

Interface names are validated. The capture command is run without a shell, and the filter is passed as a single argument.

The desktop application opens no network port, so nothing outside the app can start a capture. When you run the development server from source, keep `serve` on loopback (the default) or set `NUNMATHI_LIVE=0`.

## Engine API

The desktop application calls these endpoints in-process through its native bridge; no HTTP server is started. The same API is reachable over HTTP only when you run `python -m nunmathi serve` from source for development, which is where the `curl` example applies. Uploads send the capture as the **raw request body**, not multipart:

```bash
curl -X POST --data-binary @capture.pcap "http://127.0.0.1:8750/api/analyses?filename=capture.pcap"
```

| Method & path | Description |
|---|---|
| `GET /api/health` | Engine status and version |
| `GET /api/scenarios` | Demo scenarios |
| `GET /api/analyses` | All analyses and their status |
| `POST /api/analyses?filename=&sync=` | Upload a capture (raw body, 200 MB limit by default) |
| `POST /api/analyses/demo/{scenario}` | Forge and analyze a demo capture |
| `GET /api/analyses/{id}` | Status and progress |
| `GET /api/analyses/{id}/result` | Full result: tunnels, alerts, grade, traffic |
| `GET /api/analyses/{id}/packets?offset=&limit=&kind=` | History list (`kind` = IKE, ESP, NAT-KA or AH) |
| `GET /api/analyses/{id}/packets/{idx}` | One frame: layers, hex and IKE decode |
| `POST /api/analyses/{id}/whatif` | `{"tunnel": "T1", "changes": ["ikev2", "pq_hybrid"]}` returns the before/after grade and configs |
| `GET /api/changes` | Available What-If changes |
| `GET /api/analyses/{id}/report.{html\|json\|pdf}` | Downloadable report |
| `DELETE /api/analyses/{id}` | Delete an analysis and its capture |
| `GET /api/live/capabilities` | Capture tools (with privilege notes), interfaces, default filter |
| `GET /api/live` | Running live sessions |
| `POST /api/live` | Start: `{"interface": "eth0", "filter": "…", "backend": "dumpcap", "duration": 0, "max_packets": 1000000, "max_mb": 1024, "interval": 2}`, or replay with `replay_scenario` / `replay_analysis` and `speed` |
| `GET /api/live/{id}?after=SEQ` | Live status: counters, packet rate, per-second rates, interim grade, events after SEQ |
| `POST /api/live/{id}/stop` | Stop; the final analysis is stored like any other |
| `GET /api/live/{id}/stream` | Server-Sent Events: a `status` event every second, `end` when the capture stops |
| `GET /api/rules` | Detection rule catalogue |
| `GET /api/model-card` | Traffic model card |

In the development server, interactive OpenAPI documentation is at `/docs`. The report JSON Schema is also available from **Report → JSON Schema…** in the application and from `nunmathi schema`.

Environment variables:

- `NUNMATHI_DATA`: data directory. Default `backend/data` from source, the per-user directory above when installed.
- `NUNMATHI_MAX_UPLOAD`: upload limit in bytes.
- `NUNMATHI_FRONTEND`: directory of the built UI (development server).
- `NUNMATHI_SOFTWARE_RENDER=1|0`: force or disable software rendering of the Linux application window.
- `NUNMATHI_LIVE=0`: disable live capture in the API.
- `NUNMATHI_CAPTURE_PREFIX`: command prefix for the capture tool, e.g. `nsenter -t PID -U -n --preserve-credentials` to capture inside another network namespace.

## Tests

```bash
cd backend && python -m pytest tests -q
```

The 42 tests cover:

- pcap/pcapng parsing.
- IKE decoding and ESP geometry.
- End-to-end checks on every scenario against the forged ground truth.
- The grading rules and What-If.
- Model accuracy on a fresh synthetic seed.
- The whole REST API.
- Live mode: replay parity with the offline analysis, a stand-in capture tool streaming slowly, tool failures, stop and limits, the live REST/SSE API, and a real `dumpcap` capture on `lo` (skipped when dumpcap has no capture privileges).
- Two small fixtures cut from **real strongSwan 6.0.7 captures** (`tests/data/strongswan-*.pcap`). They check IKE crypto (including ML-KEM), PFS, Child SA and IKEv2 re-authentication lifetimes, NAT-T and ESP geometry against the known gateway configuration.

## Validation on real IPsec traffic

Besides the synthetic forge, Nunmathi was checked against real tunnels between two strongSwan 6.0.7 gateways. They ran in rootless Linux network namespaces with scripted, labelled application traffic.

| Tunnel | What Nunmathi reported (all matching the gateway configuration) |
|---|---|
| IKEv2 AES-GCM-256 / ECP-384 + ML-KEM-768 | Crypto and ML-KEM decoded, PFS enabled (ECP-384), Child SA 30 s, IKE 85 s, grade A+ |
| IKEv2 AES-CBC-128 / SHA-256 / MODP-2048, no PFS | ESP "128-bit CBC + 96-bit ICV", PFS disabled, grade B |
| IKEv1 Aggressive PSK, 3DES / SHA-1 / MODP-1024 | 64-bit block ESP, MODP-1024 flagged, grade F |
| IKEv2 with ESP-NULL | Cleartext inner headers found (NM-120), grade F |

That testing found and fixed four bugs:

- A voice-only Child SA was mislabelled as 3DES.
- IKE on port 4500 without a NAT was reported as NAT-T.
- IKEv2 re-authentication was not counted as the IKE lifetime.
- The traffic classifier scored only 46 % on real web and video windows.

The classifier now scores 98.8 % on 82 real windows and 100 % on a second capture recorded afterwards with a different traffic profile. See [docs/model-card.md](docs/model-card.md) for how to read those numbers.

## Limitations (read before relying on results)

- **The traffic classifier is trained only on synthetic traffic.** It scores 0.994 on held-out synthetic windows and 0.98–1.0 on simple scripted lab traffic (see above). It has not been measured on production traffic, and email has not been exercised on real traffic at all. Class labels are indicative. The conformal sets were calibrated on synthetic data, so their coverage is not guaranteed on real captures.
- **Short Child SAs with fixed-size traffic** can make the ESP geometry of that SA ambiguous. Nunmathi then says so, and does not guess.
- **PFS and lifetimes can only be inferred when rekeys appear in the capture.** A capture shorter than the Child SA lifetime reports PFS as `unknown` and gives only a lower bound for the lifetime.
- **Negotiated IKEv2 transforms are only visible in IKE_SA_INIT.** Everything after it is encrypted. If a capture starts mid-session, the IKE crypto is unknown and the ESP geometry is inferred from packet sizes only.
- **Live mode re-runs the full analysis periodically** (every `max(interval, 3 × analysis time)`), so on busy links interim results lag by a few seconds. ESP payloads are trimmed to 64 bytes in memory (the true length is kept); the full stream is on disk.
- **Live capture needs capture privileges** (see below). Nunmathi itself never sends packets.
