# Architecture and methodology

Nunmathi is **passive**. It reads a capture file, or a live packet stream, and never sends packets, holds keys or decrypts anything.
Every conclusion comes from cleartext IKE fields or from ESP lengths and timings, and each alert records how confident it is (`Confirmed`, `Firm` or `Tentative`).

```
capture.pcap/.pcapng
   │  pcap.py      link layers (Ethernet, VLAN, SLL/SLL2, raw IP, loopback), IPv4/IPv6 (+frag),
   │               UDP 500/4500 (NAT-T non-ESP marker, keepalive), ESP (proto 50), AH (proto 51)
   ▼
packets ──► ike.py        IKEv1/IKEv2 header + payload decoder (SA proposals/transforms, KE, Nonce,
   │                      ID, VID, Notify incl. RFC 9370 ADDITIONAL_KEY_EXCHANGE, SK/fragments)
   ▼
sessions.py   pairs peers into tunnels; tracks IKE SAs by SPI, Child SAs by ESP SPI;
   │          detects rekeys, half-open IKE_SA_INIT floods, NAT-T, DPD; infers PFS and lifetimes
   ▼
geometry.py   ESP cipher-geometry solver per SPI (see below)
   ▼
traffic.py    5 s windows → 34 features → HistGradientBoosting → conformal set, OOD flag, MEI;
   │          consecutive windows are merged into labelled segments
   ▼
assess.py     posture → rules NM-100…NM-180 → grade; What-If twin; strongSwan/libreswan configs
   ▼
analyzer.py   orchestration + progress callbacks  ──►  store.py (SQLite + files)  ──►  api.py / cli.py / report.py
```

## ESP geometry without keys

The wire format of an ESP packet is `SPI(4) | Seq(4) | IV | E(inner | pad | padlen | nh) | ICV`.
The encrypted part is padded to the cipher block size B, so every packet length L of one SA satisfies

```
L = 8 + IV + ICV + k·B
```

The residues of the observed lengths modulo 16, 8 and 4, together with the minimum length, separate these families:

- 128-bit block CBC
- 64-bit block CBC (3DES or Blowfish, which is weak)
- AEAD or counter modes

They also separate the ICV sizes (96, 128 and 192 bits).
Hypotheses the data cannot tell apart are reported together as one equivalence class, for example "AES-GCM-16 / ChaCha20-Poly1305", rather than picking one.

- **Ambiguous SAs.** A Child SA carrying only fixed-size packets (a voice call, for example) has one or two distinct lengths. Those can fit 64-bit CBC, 128-bit CBC and AEAD at once. When more than one block size fits and the chance of a spurious fit is at least 5 %, the SA is labelled **Ambiguous** with Low confidence, and every alternative is listed.
- **Tunnel geometry.** The tunnel's posture uses its best-supported Child SA: resolved before ambiguous, then by confidence and number of distinct lengths. Ambiguous SAs borrow that geometry for traffic-overhead normalisation when it is one of their consistent hypotheses.
- **Alert confidence.** NM-121 (64-bit block) is `Firm` only when the geometry confidence is High; otherwise it is `Tentative`.
ESP-NULL is detected directly because a cleartext inner IPv4 header follows the sequence number.

## PFS and lifetimes

- **Lifetimes** come from the time between successive Child SAs, where a new SPI pair replaces the old one, and between successive IKE SAs.
  For IKEv2 this covers both a CREATE_CHILD_SA IKE rekey and a **re-authentication**. With re-authentication, a completed IKE SA is replaced by a fresh IKE_SA_INIT between the same peers, which is strongSwan's default `reauth=yes`. Such IKE SAs have `origin = "reauth"`.
- **NAT traversal** (NM-162) is reported only when ESP is UDP-encapsulated (RFC 3948), or when a NAT rewrote the IKE ports.
  IKE merely moving to UDP 4500 does not count: strongSwan and others do that even without a NAT. It is exposed separately as `ike_port_4500`.
  If no rekey is seen, the capture duration is only a lower bound and is reported as "> N".
- **PFS** is judged by the size of the encrypted CREATE_CHILD_SA request. Nunmathi estimates the SK plaintext length from the negotiated cipher geometry and compares it with a rekey without KE.
  - A difference of about `8 + KE size` bytes means a KE payload is present, and gives the most likely group.
  - A difference under 24 bytes means no PFS.
  - Without any Child SA rekey in the capture, PFS is `unknown`.

## Traffic classification

- **Windows.** ESP packets are cut into 5-second windows per tunnel. Windows with fewer than 4 packets count as idle.
- **Features.** The model uses 34 features: per-direction size percentiles, inter-arrival statistics, periodicity, burstiness and direction switching.
  Packet sizes are normalised by subtracting the inferred ESP overhead, so the same model works for AEAD and CBC tunnels.
- **Model.** The classifier and the calibration are described in [model-card.md](model-card.md).

## Synthetic capture forge

`forge/` writes real, standards-conformant pcap files: IKEv1 Main/Aggressive and IKEv2, RFC 9370 IKE_INTERMEDIATE, NAT-T, and ESP with correct padding and ICV lengths. It also writes the ground-truth JSON.
tshark decodes the forged captures with 0 malformed packets.
The forge drives the demo scenarios, trains the traffic model and checks results in the test suite. Everything Nunmathi infers from a forged capture can be scored against what the forge knows it wrote.

## Storage

`store.py` keeps one SQLite table of analysis metadata under `NUNMATHI_DATA` (default `backend/data`). The uploaded capture and the result JSON are kept alongside it.
Analyses run in a background thread, and the UI polls `/api/analyses/{id}` for progress.

## Live mode

```
dumpcap / tcpdump ──stdout (pcap)──► _Tee ──► capture file (disk)
   (or replay writer, paced)          │
                                      ▼
                    iter_frames → pcap.account() → counters, per-second rates
                                      │  IPsec packets kept (ESP payload trimmed to 64 B, true length kept)
                                      ▼
   ticker: every max(interval, 3 × last analysis time) → analyze_packets() → result saved
                                      │  diff against the previous result
                                      ▼
   events: new tunnel · IKE/Child SA rekey · grade change · new alert  ──► REST + SSE, CLI
```

- **Processes.** The capture tool runs in its own process group. Stop sends SIGTERM and then SIGKILL to the whole group, so a wrapper such as `nsenter` does not leave the pipe open.
- **Parity.** The offline and live paths share `analyze_packets`. A stopped live session gives the same result as analyzing the recorded file; the tests check this.
- **Server restart.** A live analysis interrupted by a restart is re-analyzed from its partial capture file on the next start.
- **Mid-session captures** are common in live mode. When IKE_SA_INIT is not seen, the negotiated key exchange is reported as unknown. Lifetimes use only SAs born inside the capture, and lower bounds use the longest observed SA span.
