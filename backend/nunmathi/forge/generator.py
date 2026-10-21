"""IPsecForge-lite: emits realistic IKE/ESP packet captures with ground truth.

The emitted bytes follow the IKEv1/IKEv2/ESP wire formats (cleartext IKE payloads are
real structures; encrypted parts are random bytes of the exact length the negotiated
cipher would produce). Output decodes cleanly in Wireshark/tshark.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import struct

from .. import constants as C
from . import traffic_models as TM
from . import wire as W

BASE_EPOCH = 1_790_000_000        # 2026-09-21, only used for timestamps
MAC_I, MAC_R = bytes.fromhex("020000a1b2c3"), bytes.fromhex("020000d4e5f6")


class TunnelSim:
    def __init__(self, profile: dict, seed: int = 1):
        self.p = profile
        self.rng = random.Random(seed)
        self.frames: list[tuple[float, bytes]] = []
        self.truth = {"profile": profile, "class_windows": [], "child_sas": [], "ike_sas": [],
                      "events": []}
        self.ip_i = ipaddress.IPv4Address(profile.get("initiator", "198.51.100.23")).packed
        self.ip_r = ipaddress.IPv4Address(profile.get("responder", "203.0.113.10")).packed
        self.natt = profile.get("natt", False)
        self.port_i500 = self.rng.randint(20000, 60000) if self.natt else 500
        self.port_i4500 = self.rng.randint(20000, 60000) if self.natt else 4500
        self.ident = self.rng.randint(0, 65535)
        self.seq: dict[bytes, int] = {}
        self.v2 = profile.get("ike_version", 2) == 2

    # ------------------------------------------------------------ low level emit
    def _ip(self, t: float, up: bool, proto: int, payload: bytes) -> None:
        self.ident += 1
        src, dst = (self.ip_i, self.ip_r) if up else (self.ip_r, self.ip_i)
        pkt = W.ipv4(src, dst, proto, payload, self.ident)
        self.frames.append((t, W.ether(MAC_I if up else MAC_R, MAC_R if up else MAC_I, pkt)))

    def emit_ike(self, t: float, up: bool, msg: bytes, natt_port: bool = False) -> None:
        if natt_port:
            ps, pd = (self.port_i4500, 4500) if up else (4500, self.port_i4500)
            self._ip(t, up, 17, W.udp(ps, pd, b"\x00\x00\x00\x00" + msg))
        else:
            ps, pd = (self.port_i500, 500) if up else (500, self.port_i500)
            self._ip(t, up, 17, W.udp(ps, pd, msg))

    def emit_esp(self, t: float, up: bool, spi: bytes, inner: int) -> None:
        p = self.p
        encr, integ = p["esp_encr"], p.get("esp_integ", 0)
        iv, b, icv = W.esp_geometry(encr, integ)
        s = self.seq.get(spi, 0) + 1
        self.seq[spi] = s
        if p.get("tfc_padding") and encr != 11:
            # RFC 4303 §2.7: TFC padding to the path MTU inside the ciphertext; larger inner packets are
            # fragmented before encryption (pre-fragmentation), so every ESP packet leaves at one length
            inner = int(p.get("tfc_mtu", 1360))
        padded = W.pad_to(inner + 2, b)
        if encr == 11:   # ESP-NULL: inner packet is visible
            body = W.fake_inner_ip(inner, self.rng)[:inner]
            padlen = padded - inner - 2
            body += bytes(range(1, padlen + 1)) + bytes([padlen, 4]) + os.urandom(icv)
        else:
            body = os.urandom(iv + padded + icv)
        esp = spi + struct.pack("!I", s) + body
        if self.natt:
            ps, pd = (self.port_i4500, 4500) if up else (4500, self.port_i4500)
            self._ip(t, up, 17, W.udp(ps, pd, esp))
        else:
            self._ip(t, up, 50, esp)

    def event(self, t: float, kind: str, **kw) -> None:
        self.truth["events"].append({"t": round(t, 6), "kind": kind, **kw})

    # ------------------------------------------------------------ IKEv2
    def v2_sa_init(self, t: float, ispi: bytes) -> tuple[float, bytes]:
        p, rng = self.p, self.rng
        nat_d = [(41, W.notify(16388, os.urandom(20))), (41, W.notify(16389, os.urandom(20)))]
        extra_n = []
        if p.get("fragmentation", True):
            extra_n.append((41, W.notify(16430)))
        extra_n.append((41, W.notify(16431, b"\x00\x02\x00\x03\x00\x04")))
        if p.get("addke"):
            extra_n.append((41, W.notify(16438)))
        vids = [(43, bytes.fromhex(v)) for v in p.get("vendor_ids", [])]

        props = [W.proposal(1, 1, b"", W.ike_transforms(p), last=not p.get("offer_extra"))]
        for i, ex in enumerate(p.get("offer_extra", [])):
            props.append(W.proposal(i + 2, 1, b"", W.ike_transforms({**p, **ex}),
                                    last=i == len(p["offer_extra"]) - 1))
        guess = p.get("initiator_guess_group")
        zero = b"\x00" * 8
        if guess and guess != p["ike_group"]:
            req = W.ikev2_message(ispi, zero, 34, 0x08, 0, [(33, W.sa_payload(props)), (34, W.ke_payload(guess)),
                                                            (40, os.urandom(32))] + nat_d + extra_n + vids)
            self.emit_ike(t, True, req)
            t += rng.uniform(0.002, 0.02)
            resp = W.ikev2_message(ispi, zero, 34, 0x20, 0,
                                   [(41, W.notify(17, struct.pack("!H", p["ike_group"])))])
            self.emit_ike(t, False, resp)
            self.event(t, "invalid_ke", wanted=p["ike_group"], offered=guess)
            t += rng.uniform(0.005, 0.03)
        req = W.ikev2_message(ispi, zero, 34, 0x08, 0, [(33, W.sa_payload(props)), (34, W.ke_payload(p["ike_group"])),
                                                        (40, os.urandom(32))] + nat_d + extra_n + vids)
        self.emit_ike(t, True, req)
        rspi = os.urandom(8)
        t += rng.uniform(0.002, 0.03)
        chosen = [W.proposal(1, 1, b"", W.ike_transforms(p))]
        resp_pl = [(33, W.sa_payload(chosen)), (34, W.ke_payload(p["ike_group"])), (40, os.urandom(32))] + nat_d
        resp_pl += [x for x in extra_n]
        if p.get("auth", "psk") == "cert":
            resp_pl.append((38, b"\x04" + os.urandom(20)))
        resp_pl += [(43, bytes.fromhex(v)) for v in p.get("responder_vendor_ids", p.get("vendor_ids", []))]
        self.emit_ike(t, False, W.ikev2_message(ispi, rspi, 34, 0x20, 0, resp_pl))
        return t, rspi

    def v2_sk(self, t, up, ispi, rspi, exch, msgid, response, first, plain, orig_init_up=True,
              natt_port=None):
        p = self.p
        flags = (0x08 if up == orig_init_up else 0) | (0x20 if response else 0)
        natt_port = self.natt if natt_port is None else natt_port
        if p.get("fragmentation", True) and plain > 1200:
            for m in W.ikev2_skf_messages(ispi, rspi, exch, flags, msgid, first, plain, p["ike_encr"],
                                          p.get("ike_integ", 0)):
                self.emit_ike(t, up, m, natt_port)
                t += 0.0002
        else:
            self.emit_ike(t, up, W.ikev2_sk_message(ispi, rspi, exch, flags, msgid, first, plain,
                                                   p["ike_encr"], p.get("ike_integ", 0)), natt_port)
        return t

    def v2_establish(self, t: float) -> dict:
        p, rng = self.p, self.rng
        ispi = os.urandom(8)
        t, rspi = self.v2_sa_init(t, ispi)
        msgid = 1
        for g in p.get("addke", []):
            t += rng.uniform(0.01, 0.05)
            self.v2_sk(t, True, ispi, rspi, 43, msgid, False, 34, 8 + C.KE_SIZE[g], natt_port=self.natt)
            t += rng.uniform(0.002, 0.02)
            ct = {35: 768, 36: 1088, 37: 1568}.get(g, C.KE_SIZE[g])
            self.v2_sk(t, False, ispi, rspi, 43, msgid, True, 34, 8 + ct, natt_port=self.natt)
            msgid += 1
        cert = p.get("auth", "psk") == "cert"
        cp = 28 if p.get("remote_access") else 0
        t += rng.uniform(0.01, 0.05)
        self.v2_sk(t, True, ispi, rspi, 35, msgid, False, 35, (1480 if cert else 250) + cp)
        t += rng.uniform(0.01, 0.08)
        self.v2_sk(t, False, ispi, rspi, 35, msgid, True, 36, (1420 if cert else 220) + cp)
        ike = {"ispi": ispi.hex(), "rspi": rspi.hex(), "start": t, "group": p["ike_group"],
               "addke": p.get("addke", []), "msgid": msgid + 1, "via": "IKE_SA_INIT"}
        self.truth["ike_sas"].append(ike)
        self.event(t, "ike_established", ispi=ike["ispi"])
        return ike

    def v2_child_rekey(self, t: float, ike: dict) -> float:
        p = self.p
        ke = 8 + C.KE_SIZE[p["pfs_group"]] if p.get("pfs_group") else 0
        sa = 48 if p["esp_encr"] not in C.AEAD_ENCR else 40
        ii, rr = bytes.fromhex(ike["ispi"]), bytes.fromhex(ike["rspi"])
        self.v2_sk(t, True, ii, rr, 36, ike["msgid"], False, 41, 12 + sa + 36 + ke + 48)
        t += self.rng.uniform(0.005, 0.05)
        self.v2_sk(t, False, ii, rr, 36, ike["msgid"], True, 33, sa + 36 + ke + 48)
        ike["msgid"] += 1
        return t

    def v2_delete(self, t: float, ike: dict, n_spis: int = 1, ike_delete: bool = False) -> float:
        ii, rr = bytes.fromhex(ike["ispi"]), bytes.fromhex(ike["rspi"])
        plain = 8 if ike_delete else 8 + 4 * n_spis
        self.v2_sk(t, True, ii, rr, 37, ike["msgid"], False, 42, plain)
        t += self.rng.uniform(0.005, 0.05)
        self.v2_sk(t, False, ii, rr, 37, ike["msgid"], True, 42 if not ike_delete else 0,
                   plain if not ike_delete else 0)
        ike["msgid"] += 1
        return t

    def v2_ike_rekey(self, t: float, ike: dict) -> dict:
        p = self.p
        ke = 8 + C.KE_SIZE[p["ike_group"]]
        sa = 8 + 8 + 4 * 8 + (4 if p.get("ike_keylen") else 0) + 8 * len(p.get("addke", []))
        ii, rr = bytes.fromhex(ike["ispi"]), bytes.fromhex(ike["rspi"])
        self.v2_sk(t, True, ii, rr, 36, ike["msgid"], False, 33, sa + 36 + ke)
        t += self.rng.uniform(0.005, 0.05)
        self.v2_sk(t, False, ii, rr, 36, ike["msgid"], True, 33, sa + 36 + ke)
        ike["msgid"] += 1
        new = {"ispi": os.urandom(8).hex(), "rspi": os.urandom(8).hex(), "start": t, "group": p["ike_group"],
               "addke": p.get("addke", []), "msgid": 0, "via": "CREATE_CHILD_SA"}
        t += 0.3
        self.v2_delete(t, ike, ike_delete=True)
        self.truth["ike_sas"].append(new)
        self.event(t, "ike_rekey", old=ike["ispi"], new=new["ispi"])
        return new

    def v2_dpd(self, t: float, ike: dict) -> None:
        ii, rr = bytes.fromhex(ike["ispi"]), bytes.fromhex(ike["rspi"])
        up = self.rng.random() < 0.5
        self.v2_sk(t, up, ii, rr, 37, ike["msgid"], False, 0, 0)
        self.v2_sk(t + self.rng.uniform(0.01, 0.06), not up, ii, rr, 37, ike["msgid"], True, 0, 0)
        ike["msgid"] += 1

    # ------------------------------------------------------------ IKEv1
    def _v1_transforms(self) -> list[dict]:
        p = self.p
        enc = {v: k for k, v in C.V1_TO_V2_ENCR.items()}[p["ike_encr"]]
        hsh = {v: k for k, v in C.V1_TO_V2_PRF.items()}[p["ike_prf"]]
        base = {1: enc, 2: hsh, 3: p.get("v1_auth", 1), 4: p["ike_group"], 11: 1, 12: p["ike_lifetime"]}
        if p.get("ike_keylen"):
            base[14] = p["ike_keylen"]
        out = [base]
        for ex in p.get("offer_extra", []):
            e = dict(base)
            e[1] = {v: k for k, v in C.V1_TO_V2_ENCR.items()}.get(ex.get("ike_encr", p["ike_encr"]), enc)
            e[4] = ex.get("ike_group", p["ike_group"])
            e.pop(14, None)
            out.append(e)
        return out

    def v1_phase1(self, t: float) -> dict:
        p, rng = self.p, self.rng
        ic, zero = os.urandom(8), b"\x00" * 8
        rc = os.urandom(8)
        vids = [(13, bytes.fromhex(v)) for v in p.get("vendor_ids", [])]
        tr = self._v1_transforms()
        ks = C.KE_SIZE[p["ike_group"]]
        ident = p.get("v1_identity", "vpn-user@corp.example").encode()
        id_pl = bytes([3, 17, 1, 244]) + ident   # ID_USER_FQDN, UDP/500
        natd = [(20, os.urandom(20)), (20, os.urandom(20))]
        if p.get("v1_mode") == "aggressive":
            self.emit_ike(t, True, W.ikev1_message(ic, zero, 4, 0, 0, [(1, W.v1_sa(tr)), (4, os.urandom(ks)),
                                                                        (10, os.urandom(20)), (5, id_pl)] + vids))
            t += rng.uniform(0.005, 0.04)
            rid = bytes([1, 17, 1, 244]) + self.ip_r
            self.emit_ike(t, False, W.ikev1_message(ic, rc, 4, 0, 0, [(1, W.v1_sa(tr[:1])), (4, os.urandom(ks)),
                                                                       (10, os.urandom(20)), (5, rid),
                                                                       (8, os.urandom(20))] + natd + vids))
            t += rng.uniform(0.005, 0.04)
            self.emit_ike(t, True, W.ikev1_encrypted(ic, rc, 4, 0, 8, 28, p["ike_encr"], 0), self.natt)
        else:
            self.emit_ike(t, True, W.ikev1_message(ic, zero, 2, 0, 0, [(1, W.v1_sa(tr))] + vids))
            t += rng.uniform(0.005, 0.04)
            self.emit_ike(t, False, W.ikev1_message(ic, rc, 2, 0, 0, [(1, W.v1_sa(tr[:1]))] + vids))
            t += rng.uniform(0.005, 0.04)
            self.emit_ike(t, True, W.ikev1_message(ic, rc, 2, 0, 0, [(4, os.urandom(ks)), (10, os.urandom(20))] + natd))
            t += rng.uniform(0.005, 0.04)
            self.emit_ike(t, False, W.ikev1_message(ic, rc, 2, 0, 0, [(4, os.urandom(ks)), (10, os.urandom(20))] + natd))
            t += rng.uniform(0.005, 0.04)
            self.emit_ike(t, True, W.ikev1_encrypted(ic, rc, 2, 0, 5, 12 + len(ident) + 24, p["ike_encr"], 0), self.natt)
            t += rng.uniform(0.005, 0.04)
            self.emit_ike(t, False, W.ikev1_encrypted(ic, rc, 2, 0, 5, 16 + 24, p["ike_encr"], 0), self.natt)
        ike = {"ispi": ic.hex(), "rspi": rc.hex(), "start": t, "group": p["ike_group"], "addke": [],
               "msgid": 0, "via": "Aggressive Mode" if p.get("v1_mode") == "aggressive" else "Main Mode"}
        self.truth["ike_sas"].append(ike)
        self.event(t, "ike_established", ispi=ike["ispi"])
        return ike

    def v1_quick_mode(self, t: float, ike: dict) -> float:
        p, rng = self.p, self.rng
        ic, rc = bytes.fromhex(ike["ispi"]), bytes.fromhex(ike["rspi"])
        mid = rng.getrandbits(32)
        ke = 4 + C.KE_SIZE[p["pfs_group"]] if p.get("pfs_group") else 0
        base = 24 + 60 + 24 + 16 + 16
        self.emit_ike(t, True, W.ikev1_encrypted(ic, rc, 32, mid, 8, base + ke, p["ike_encr"], 0), self.natt)
        t += rng.uniform(0.005, 0.05)
        self.emit_ike(t, False, W.ikev1_encrypted(ic, rc, 32, mid, 8, base + ke, p["ike_encr"], 0), self.natt)
        t += rng.uniform(0.005, 0.05)
        self.emit_ike(t, True, W.ikev1_encrypted(ic, rc, 32, mid, 8, 24, p["ike_encr"], 0), self.natt)
        return t

    def v1_info(self, t: float, ike: dict, plain: int, reply: bool = True) -> None:
        ic, rc = bytes.fromhex(ike["ispi"]), bytes.fromhex(ike["rspi"])
        up = self.rng.random() < 0.5
        self.emit_ike(t, up, W.ikev1_encrypted(ic, rc, 5, self.rng.getrandbits(32), 8, plain, self.p["ike_encr"], 0), self.natt)
        if reply:
            self.emit_ike(t + self.rng.uniform(0.01, 0.06), not up,
                          W.ikev1_encrypted(ic, rc, 5, self.rng.getrandbits(32), 8, plain, self.p["ike_encr"], 0), self.natt)

    # ------------------------------------------------------------ extras
    def half_open_flood(self, t: float, n: int) -> None:
        p = self.p
        for k in range(n):
            src = ipaddress.IPv4Address(self.rng.getrandbits(32) | 0x01000000).packed
            ispi = os.urandom(8)
            req = W.ikev2_message(ispi, b"\x00" * 8, 34, 0x08, 0,
                                  [(33, W.sa_payload([W.proposal(1, 1, b"", W.ike_transforms(p))])),
                                   (34, W.ke_payload(p["ike_group"])), (40, os.urandom(32))])
            tt = t + k * self.rng.uniform(0.02, 0.2)
            self.ident += 1
            pkt = W.ipv4(src, self.ip_r, 17, W.udp(self.rng.randint(1024, 65535), 500, req), self.ident)
            self.frames.append((tt, W.ether(MAC_I, MAC_R, pkt)))
            if k >= 20:   # responder switches to stateless cookies
                resp = W.ikev2_message(ispi, b"\x00" * 8, 34, 0x20, 0, [(41, W.notify(16390, os.urandom(20)))])
                pkt = W.ipv4(self.ip_r, src, 17, W.udp(500, 500, resp), self.ident)
                self.frames.append((tt + 0.001, W.ether(MAC_R, MAC_I, pkt)))
        self.event(t, "half_open_flood", count=n)

    # ------------------------------------------------------------ main driver
    def run(self) -> None:
        p, rng = self.p, self.rng
        dur = float(p["duration"])

        # --- 1. decide application traffic windows (times only)
        n_win = p.get("active_windows", 12)
        lo, hi = p.get("window_len", (15, 30))
        classes = p.get("classes", TM.CLASSES)
        slots = sorted(rng.uniform(5, dur - hi - 5) for _ in range(n_win))
        windows, busy_until = [], 0.0
        for i, s in enumerate(slots):
            s = max(s, busy_until + 3)
            if s + lo > dur - 2:
                break
            wlen = rng.uniform(lo, hi)
            cls = classes[i % len(classes)] if p.get("round_robin", True) else rng.choice(classes)
            windows.append((s, s + wlen, cls))
            busy_until = s + wlen

        # --- 2. control plane, processed in chronological order so message IDs stay monotonic
        t = 0.5
        ike = self.v2_establish(t) if self.v2 else self.v1_phase1(t)
        if not self.v2:
            self.v1_quick_mode(ike["start"] + 0.05, ike)
        t = ike["start"] + 0.1
        child_life = p["child_lifetime"] * rng.uniform(0.9, 0.97)
        ike_life = p["ike_lifetime"] * rng.uniform(0.9, 0.97)
        epochs = [(t, os.urandom(4), os.urandom(4))]
        self._child(epochs[0], None)
        dpd = p.get("dpd", 300)
        next_child, next_ike, next_dpd = t + child_life, t + ike_life, float(dpd)

        def busy(x: float) -> bool:
            return any(a - 2 <= x <= b + 2 for a, b, _ in windows)

        while min(next_child, next_ike, next_dpd) < dur - 1:
            nxt = min(next_child, next_ike, next_dpd)
            if nxt == next_dpd:
                if not busy(nxt):
                    if self.v2:
                        self.v2_dpd(nxt, ike)
                    else:
                        self.v1_info(nxt, ike, 28 + 24)
                next_dpd = nxt + dpd * rng.uniform(0.95, 1.05)
            elif nxt == next_ike:
                tt = nxt
                if self.v2:
                    ike = self.v2_ike_rekey(tt, ike)
                else:   # IKEv1: full re-authentication, new phase 1 + quick mode
                    self.v1_info(tt + 1.0, ike, 16 + 24, reply=False)
                    ike = self.v1_phase1(tt)
                    tt = self.v1_quick_mode(ike["start"] + 0.05, ike)
                    ep = (tt + 0.01, os.urandom(4), os.urandom(4))
                    epochs.append(ep)
                    self._child(ep, bool(p.get("pfs_group")))
                    next_child = tt + child_life
                next_ike = tt + ike_life
            else:
                tt = self.v2_child_rekey(nxt, ike) if self.v2 else self.v1_quick_mode(nxt, ike)
                ep = (tt + 0.01, os.urandom(4), os.urandom(4))
                epochs.append(ep)
                self._child(ep, bool(p.get("pfs_group")))
                self.event(tt, "child_rekey", pfs=bool(p.get("pfs_group")))
                if self.v2:
                    self.v2_delete(tt + 0.5, ike)
                else:
                    self.v1_info(tt + 0.5, ike, 16 + 24 + 4)
                next_child = tt + child_life

        # --- 3. data plane
        for s, e, cls in windows:
            inner = TM.generate(cls, rng, e - s)
            for off, d, ln in inner:
                ts = s + off
                ep = max((x for x in epochs if x[0] <= ts), key=lambda x: x[0])
                self.emit_esp(ts, d == "up", ep[2] if d == "up" else ep[1], ln)
            self.truth["class_windows"].append({"start": s, "end": e, "class": cls, "packets": len(inner)})

        if self.natt:
            k = 20.0
            while k < dur:
                self.ident += 1
                pkt = W.ipv4(self.ip_i, self.ip_r, 17, W.udp(self.port_i4500, 4500, b"\xff"), self.ident)
                self.frames.append((k, W.ether(MAC_I, MAC_R, pkt)))
                k += 20.0
        if p.get("half_open_flood"):
            self.half_open_flood(p.get("flood_at", dur * 0.4), p["half_open_flood"])

    def _child(self, ep, pfs) -> None:
        self.truth["child_sas"].append({"start": ep[0], "spi_up": ep[1].hex(), "spi_down": ep[2].hex(),
                                        "rekeyed_with_pfs": pfs})

    def write(self, pcap_path: str, truth_path: str | None = None) -> dict:
        self.frames.sort(key=lambda f: f[0])
        w = W.PcapWriter(pcap_path)
        for ts, fr in self.frames:
            w.write(BASE_EPOCH + ts, fr)
        w.close()
        truth = self.truth
        truth["frames"] = w.count
        truth["base_epoch"] = BASE_EPOCH
        truth["esp_geometry"] = list(W.esp_geometry(self.p["esp_encr"], self.p.get("esp_integ", 0)))
        if truth_path:
            with open(truth_path, "w") as fh:
                json.dump(truth, fh, indent=1, default=str)
        return truth


def forge(profile: dict, pcap_path: str, truth_path: str | None = None, seed: int = 1) -> dict:
    sim = TunnelSim(profile, seed)
    sim.run()
    return sim.write(pcap_path, truth_path)
