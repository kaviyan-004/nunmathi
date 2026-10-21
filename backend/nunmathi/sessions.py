"""Reconstruct tunnels, IKE SAs, Child SAs, rekeys and PFS from passively observed packets."""
from __future__ import annotations

import statistics
from collections import defaultdict

from . import constants as C
from . import geometry
from .forge.wire import ike_geometry, pad_to
from .ike import IKEMessage, IKEParseError, parse
from .pcap import Packet

ZERO_SPI = "0" * 16


def _crypto_from_proposal(prop) -> dict:
    out = {"encr": None, "keylen": None, "prf": None, "integ": None, "group": None, "addke": []}
    for t in prop.transforms:
        if t.ttype == 1 and out["encr"] is None:
            out["encr"], out["keylen"] = t.tid, t.keylen
        elif t.ttype == 2 and out["prf"] is None:
            out["prf"] = t.tid
        elif t.ttype == 3 and out["integ"] is None:
            out["integ"] = t.tid
        elif t.ttype == 4 and out["group"] is None:
            out["group"] = t.tid
        elif t.ttype >= 6:
            out["addke"].append(t.tid)
    return out


def crypto_names(c: dict) -> dict:
    if not c:
        return {}
    enc = C.ENCR.get(c.get("encr"), f"#{c.get('encr')}") if c.get("encr") is not None else None
    if enc and c.get("keylen"):
        enc = f"{enc}_{c['keylen']}"
    return {"encr": enc, "prf": C.PRF.get(c.get("prf")) if c.get("prf") else None,
            "integ": C.INTEG.get(c.get("integ")) if c.get("integ") else None,
            "group": C.KE.get(c.get("group")) if c.get("group") is not None else None,
            "addke": [C.KE.get(g, str(g)) for g in c.get("addke", [])]}


# typical contents of encrypted IKEv2 exchanges (RFC 7296); shown as "inferred", never as observed
_V2_INFERRED = {
    (35, False): "SK{IDi, [CERT], AUTH, SA, TSi, TSr}", (35, True): "SK{IDr, [CERT], AUTH, SA, TSi, TSr}",
    (36, False): "SK{SA, Ni, [KEi], [TSi, TSr]}", (36, True): "SK{SA, Nr, [KEr], [TSi, TSr]}",
    (37, False): "SK{[N], [D], [CP]}", (37, True): "SK{[N], [D], [CP]}",
    (43, False): "SK{ADDKE / IKE_INTERMEDIATE data}", (43, True): "SK{ADDKE / IKE_INTERMEDIATE data}",
    (44, False): "SK{KE (additional key exchange)}", (44, True): "SK{KE (additional key exchange)}",
}


class IKESA:
    def __init__(self, ispi: str, version: int):
        self.ispi, self.rspi, self.version = ispi, ZERO_SPI, version
        self.msgs: list[tuple[Packet, IKEMessage]] = []
        self.initiator = self.responder = None
        self.offered: list = []
        self.chosen: dict | None = None
        self.origin = None
        self.parent = None
        self.reauth = False
        self.first_ts = self.last_ts = None

    def add(self, pkt: Packet, m: IKEMessage) -> None:
        self.msgs.append((pkt, m))
        self.first_ts = pkt.ts if self.first_ts is None else min(self.first_ts, pkt.ts)
        self.last_ts = pkt.ts if self.last_ts is None else max(self.last_ts, pkt.ts)
        if m.rspi != ZERO_SPI:
            self.rspi = m.rspi

    def finish(self) -> None:
        first_pkt, first = self.msgs[0]
        if self.version == 2:
            init_msgs = [(p, m) for p, m in self.msgs if m.initiator and not m.response]
            p0 = init_msgs[0][0] if init_msgs else first_pkt
            self.initiator, self.responder = (p0.src, p0.dst)
            sa_init = [(p, m) for p, m in self.msgs if m.exchange == 34]
            self.origin = "IKE_SA_INIT" if sa_init else "rekey"
            reqs = [m for p, m in sa_init if not m.response and m.proposals]
            resps = [m for p, m in sa_init if m.response and m.proposals]
            if reqs:
                self.offered = [_crypto_from_proposal(pr) for pr in reqs[-1].proposals]
            if resps:
                self.chosen = _crypto_from_proposal(resps[-1].proposals[0])
        else:
            self.initiator, self.responder = first_pkt.src, first_pkt.dst
            self.origin = C.EXCHANGE_V1.get(first.exchange, "IKEv1") if first.exchange in (2, 4) else "rekey"
            reqs = [m for p, m in self.msgs if m.proposals and m.rspi == ZERO_SPI]
            resps = [m for p, m in self.msgs if m.proposals and m.rspi != ZERO_SPI]
            if reqs:
                self.offered = [_crypto_from_proposal(pr) for pr in reqs[0].proposals]
            if resps:
                self.chosen = _crypto_from_proposal(resps[0].proposals[0])
            elif reqs and len(reqs[0].proposals) == 1:
                self.chosen = self.offered[0]

    # convenience -----------------------------------------------------
    def exchanges(self, code: int) -> list[tuple[Packet, IKEMessage]]:
        return [(p, m) for p, m in self.msgs if m.exchange == code]

    def established(self) -> bool:
        if self.version == 2:
            return any(m.exchange == 35 and m.response for _, m in self.msgs) or self.origin == "rekey"
        return any(m.encrypted for _, m in self.msgs) and self.rspi != ZERO_SPI

    def notifies(self) -> set[int]:
        return {n for _, m in self.msgs for n in m.notifies}

    def to_dict(self) -> dict:
        v2 = self.version == 2
        sa_init = self.exchanges(34) if v2 else [x for x in self.msgs if x[1].exchange in (2, 4)]
        vids_i = sorted({v for p, m in self.msgs if p.src == self.initiator for v in m.vendor_ids})
        vids_r = sorted({v for p, m in self.msgs if p.src == self.responder for v in m.vendor_ids})
        from .ike import vendor_name
        frag_i = any(16430 in m.notifies for p, m in sa_init if p.src == self.initiator)
        frag_r = any(16430 in m.notifies for p, m in sa_init if p.src == self.responder)
        ids = sorted({i for _, m in self.msgs for i in m.identities})
        ex_counts: dict[str, int] = defaultdict(int)
        for _, m in self.msgs:
            ex_counts[m.exchange_name] += 1
        wanted = None
        for _, m in self.msgs:
            for pl in m.payloads:
                if pl.get("wanted_group"):
                    wanted = pl["wanted_group"]
        v1_life = next((m.v1_life for _, m in self.msgs if m.v1_life), {})
        return {
            "ispi": self.ispi, "rspi": self.rspi, "version": self.version, "origin": "reauth" if self.reauth else self.origin,
            "parent": self.parent, "initiator": self.initiator, "responder": self.responder,
            "first_ts": self.first_ts, "last_ts": self.last_ts, "messages": len(self.msgs),
            "established": self.established(),
            "offered": [dict(c, names=crypto_names(c)) for c in self.offered],
            "chosen": dict(self.chosen, names=crypto_names(self.chosen)) if self.chosen else None,
            "inherited_crypto": False,
            "exchanges": dict(ex_counts),
            "notifies": sorted(C.NOTIFY.get(n, str(n)) for n in self.notifies()),
            "invalid_ke_wanted": wanted,
            "vendor_ids": {"initiator": [{"hex": v, "name": vendor_name(v)} for v in vids_i],
                           "responder": [{"hex": v, "name": vendor_name(v)} for v in vids_r]},
            "fragmentation": {"initiator": frag_i, "responder": frag_r},
            "nat_t": any(p.sport == 4500 or p.dport == 4500 for p, _ in self.msgs),
            "nat_detected": any(p.sport not in (500, 4500) or p.dport not in (500, 4500) for p, _ in self.msgs),
            "intermediate": [m.sk_len for _, m in self.exchanges(43)] if v2 else [],
            "identities": ids,
            "cleartext_hash": any(m.cleartext_hash for _, m in self.msgs),
            "aggressive": any(m.exchange == 4 for _, m in self.msgs) if not v2 else False,
            "v1_lifetime": v1_life,
            "v1_auth": next((m.v1_auth for _, m in self.msgs if m.v1_auth), None),
            "packets": [p.idx for p, _ in self.msgs],
            "ladder": self.ladder(),
        }

    def ladder(self, limit: int = 400) -> list[dict]:
        """Message sequence for the IKE ladder diagram, in capture order."""
        out = []
        for p, m in sorted(self.msgs, key=lambda x: x[0].ts)[:limit]:
            names = [pl.get("type") for pl in m.payloads if not (m.notifies and pl.get("type") == "Notify")]
            names += [f"N({C.NOTIFY.get(n, n)})" for n in m.notifies]
            inferred = None
            if self.version == 2 and m.encrypted:
                inferred = _V2_INFERRED.get((m.exchange, m.response))
            out.append({"t": p.ts, "packet": p.idx, "src": p.src, "dst": p.dst,
                        "from_initiator": p.src == self.initiator, "exchange": m.exchange_name,
                        "msgid": m.msgid, "response": m.response, "length": m.length, "sk_len": m.sk_len,
                        "fragment": list(m.fragment) if m.fragment else None,
                        "payloads": [n for n in names if n and n != "NONE"], "inferred": inferred,
                        "ke_group": C.KE.get(m.ke_group) if m.ke_group else None})
        return out


def _length_hist(out_l: list[int], in_l: list[int], top: int = 60) -> dict:
    """Exact per-length counts (ESP lengths are few and discrete); keeps the most frequent lengths."""
    cnt: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    for L in out_l:
        cnt[L][0] += 1
    for L in in_l:
        cnt[L][1] += 1
    keep = sorted(sorted(cnt, key=lambda L: -(cnt[L][0] + cnt[L][1]))[:top])
    return {"lengths": keep, "out": [cnt[L][0] for L in keep], "in": [cnt[L][1] for L in keep],
            "distinct": len(cnt), "truncated": len(cnt) > top}


def _pair_key(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a < b else (b, a)


def _plain_estimate(sk_len: int, crypto: dict | None, version: int) -> tuple[float, int]:
    """Estimate the SK plaintext length of an encrypted IKE message: (estimate, uncertainty)."""
    if not crypto or crypto.get("encr") is None:
        return float(sk_len - 32), 16
    iv, b, icv = ike_geometry(crypto["encr"], crypto.get("integ") or 0)
    if version == 1:
        return float(sk_len - b / 2), b
    return float(sk_len - iv - icv - 1 - (b - 1) / 2), max(b, 4)


def _infer_pfs(delta: float, tol: float, prefer: list[int]) -> tuple[bool, int | None, str]:
    if delta < 24:
        return False, None, "High" if delta < 8 else "Medium"
    best, err = None, 1e9
    for g in prefer + [14, 15, 16, 19, 20, 21, 31, 32, 2, 5]:
        size = C.KE_SIZE.get(g)
        if size is None:
            continue
        e = abs(delta - (8 + size))
        if e < err - 1e-9:
            best, err = g, e
    conf = "High" if err <= tol + 12 else "Medium" if err <= 64 else "Low"
    return True, best, conf


def analyze_sessions(packets: list[Packet]) -> dict:
    ike_msgs: list[tuple[Packet, IKEMessage]] = []
    parse_errors = 0
    for p in packets:
        if p.kind == "IKE":
            try:
                ike_msgs.append((p, parse(p.payload)))
            except IKEParseError:
                parse_errors += 1

    # ---------------- IKE SAs
    sas: dict[str, IKESA] = {}
    for p, m in ike_msgs:
        sa = sas.get(m.ispi)
        if sa is None:
            sa = sas[m.ispi] = IKESA(m.ispi, m.version)
        sa.add(p, m)
    for sa in sas.values():
        sa.finish()

    # half-open handshakes: IKE_SA_INIT requests that never completed and carry no ESP
    esp_pairs = {_pair_key(p.src, p.dst) for p in packets if p.kind == "ESP"}
    tunnels_sas: dict[tuple, list[IKESA]] = defaultdict(list)
    half_open = defaultdict(lambda: {"attempts": 0, "sources": set(), "cookies": 0, "first": None, "last": None})
    for sa in sas.values():
        key = _pair_key(sa.initiator, sa.responder)
        if not sa.established() and key not in esp_pairs:
            h = half_open[sa.responder]
            h["attempts"] += 1
            h["sources"].add(sa.initiator)
            h["cookies"] += int(16390 in sa.notifies())
            h["first"] = sa.first_ts if h["first"] is None else min(h["first"], sa.first_ts)
            h["last"] = sa.last_ts if h["last"] is None else max(h["last"], sa.last_ts)
            continue
        tunnels_sas[key].append(sa)

    # ---------------- ESP by SPI
    spis: dict[tuple, dict] = {}
    for p in packets:
        if p.kind != "ESP" or p.size < 8:
            continue
        spi = p.payload[:4].hex()
        k = (spi, p.src, p.dst)
        s = spis.get(k)
        if s is None:
            s = spis[k] = {"spi": spi, "src": p.src, "dst": p.dst, "first_ts": p.ts, "last_ts": p.ts,
                           "packets": 0, "bytes": 0, "lengths": [], "sample": [], "ts": [], "seq_first": None,
                           "seq_last": None, "udp_encap": p.l4 == "UDP", "idx": []}
            s["seq_first"] = int.from_bytes(p.payload[4:8], "big")
        s["last_ts"] = p.ts
        s["packets"] += 1
        s["bytes"] += p.size
        s["lengths"].append(p.size)
        s["ts"].append(p.ts)
        s["seq_last"] = int.from_bytes(p.payload[4:8], "big")
        if len(s["sample"]) < 400:
            s["sample"].append(p.payload)
        if len(s["idx"]) < 5:
            s["idx"].append(p.idx)
    for key, s in spis.items():
        tunnels_sas.setdefault(_pair_key(s["src"], s["dst"]), [])

    # ---------------- tunnels
    tunnels = []
    for n, (key, sa_list) in enumerate(sorted(tunnels_sas.items(), key=lambda kv: min(
            [x.first_ts for x in kv[1]] or [min(s["first_ts"] for s in spis.values()
                                                 if _pair_key(s["src"], s["dst"]) == kv[0])])), 1):
        sa_list.sort(key=lambda s: s.first_ts)
        tunnels.append(_build_tunnel(n, key, sa_list, [s for s in spis.values() if _pair_key(s["src"], s["dst"]) == key]))

    ho = [{"responder": r, "attempts": h["attempts"], "distinct_sources": len(h["sources"]), "cookies": h["cookies"],
           "first_ts": h["first"], "last_ts": h["last"],
           "rate_per_s": round(h["attempts"] / max(1e-3, (h["last"] or 0) - (h["first"] or 0)), 2)}
          for r, h in half_open.items()]
    return {"tunnels": tunnels, "half_open": ho, "ike_parse_errors": parse_errors,
            "ike_messages": len(ike_msgs)}


def _build_tunnel(n: int, key: tuple, sa_list: list[IKESA], spi_list: list[dict]) -> dict:
    root = next((s for s in sa_list if s.origin != "rekey"), sa_list[0] if sa_list else None)
    initiator = root.initiator if root else spi_list[0]["src"]
    responder = root.responder if root else spi_list[0]["dst"]
    version = root.version if root else None

    # link rekeyed IKE SAs to parents, inheriting crypto (it is encrypted in CREATE_CHILD_SA)
    ike_rekey_times, ike_rekey_pkts = [], set()
    for i, sa in enumerate(sa_list):
        if sa.origin == "rekey" and i > 0:
            parent = sa_list[i - 1]
            sa.parent = parent.ispi
            if sa.chosen is None and parent.chosen:
                sa.chosen = dict(parent.chosen)
                sa.inherited = True
            # the IKE rekey is the parent's last CREATE_CHILD_SA request before the new SPI appears
            ccs = [p for p, m in parent.exchanges(36) if not m.response and p.ts <= sa.first_ts]
            if ccs:
                ike_rekey_pkts.add(ccs[-1].idx)
                ike_rekey_times.append(ccs[-1].ts)
            else:
                ike_rekey_times.append(sa.first_ts)
        elif sa.origin != "rekey" and i > 0 and sa.version == 1:
            sa.parent = sa_list[i - 1].ispi
            ike_rekey_times.append(sa.first_ts)
        elif sa.origin == "IKE_SA_INIT" and i > 0 and sa.version == 2 and sa.established() \
                and sa_list[i - 1].established():
            # IKEv2 re-authentication (e.g. strongSwan reauth=yes): a fresh IKE_SA_INIT replaces the IKE SA
            sa.parent = sa_list[i - 1].ispi
            sa.reauth = True
            ike_rekey_times.append(sa.first_ts)
    ike_crypto = root.chosen if root else None

    # ---------- CREATE_CHILD_SA / Quick Mode analysis
    child_events, pfs_evidence = [], []
    for sa in sa_list:
        crypto = sa.chosen or ike_crypto
        if sa.version == 2:
            for p, m in sa.exchanges(36):
                if m.response or m.fragment and m.fragment[0] != 1:
                    continue
                is_ike_rekey = p.idx in ike_rekey_pkts
                est, tol = _plain_estimate(m.sk_len, crypto, 2)
                base = 12 + (40 if crypto and crypto.get("encr") in C.AEAD_ENCR else 48) + 36 + 48
                if is_ike_rekey:
                    child_events.append({"t": p.ts, "kind": "ike_rekey", "packet": p.idx, "sk_len": m.sk_len})
                    continue
                delta = est - base
                pfs, grp, conf = _infer_pfs(delta, tol, [crypto.get("group")] if crypto and crypto.get("group") else [])
                ev = {"t": p.ts, "kind": "child_rekey", "packet": p.idx, "sk_len": m.sk_len,
                      "plain_est": round(est), "delta": round(delta), "pfs": pfs,
                      "pfs_group": C.KE.get(grp) if grp else None, "pfs_group_id": grp, "confidence": conf}
                child_events.append(ev)
                pfs_evidence.append(ev)
        else:
            qm = [(p, m) for p, m in sa.msgs if m.exchange == 32]
            first_qm = {}
            for p, m in qm:
                first_qm.setdefault(m.msgid, (p, m))
            for idx_q, (p, m) in enumerate(sorted(first_qm.values(), key=lambda x: x[0].ts)):
                est, tol = _plain_estimate(m.sk_len, crypto, 1)
                delta = est - 140
                pfs, grp, conf = _infer_pfs(delta, tol, [crypto.get("group")] if crypto and crypto.get("group") else [])
                ev = {"t": p.ts, "kind": "quick_mode", "packet": p.idx, "sk_len": m.sk_len,
                      "plain_est": round(est), "delta": round(delta), "pfs": pfs,
                      "pfs_group": C.KE.get(grp) if grp else None, "pfs_group_id": grp, "confidence": conf,
                      "initial": idx_q == 0 and sa is sa_list[0]}
                child_events.append(ev)
                pfs_evidence.append(ev)
    child_events.sort(key=lambda e: e["t"])

    # ---------- child SAs from ESP SPIs
    up = sorted([s for s in spi_list if s["src"] == initiator], key=lambda s: s["first_ts"])
    down = sorted([s for s in spi_list if s["src"] != initiator], key=lambda s: s["first_ts"])
    children, used = [], set()
    for s in up:
        best, ov = None, -1e18
        for d in down:
            if d["spi"] in used:
                continue
            o = min(s["last_ts"], d["last_ts"]) - max(s["first_ts"], d["first_ts"])
            if o > ov:
                best, ov = d, o
        if best is not None and ov > -600:
            used.add(best["spi"])
        children.append((s, best if best is not None and ov > -600 else None))
    for d in down:
        if d["spi"] not in used:
            children.append((None, d))
    children.sort(key=lambda c: min(x["first_ts"] for x in c if x))

    child_out = []
    for i, (u, d) in enumerate(children, 1):
        lengths = (u["lengths"] if u else []) + (d["lengths"] if d else [])
        sample = (u["sample"] if u else []) + (d["sample"] if d else [])
        geo = geometry.solve(lengths, sample)
        geo["mode"] = geometry.infer_mode(lengths, geo.get("best"), geo.get("esp_null"))
        geo["length_hist"] = _length_hist(u["lengths"] if u else [], d["lengths"] if d else [])
        first = min(x["first_ts"] for x in (u, d) if x)
        last = max(x["last_ts"] for x in (u, d) if x)
        child_out.append({
            "id": f"T{n}.C{i}",
            "spi_out": u["spi"] if u else None, "spi_in": d["spi"] if d else None,
            "first_ts": first, "last_ts": last,
            "packets": sum(x["packets"] for x in (u, d) if x), "bytes": sum(x["bytes"] for x in (u, d) if x),
            "packets_out": u["packets"] if u else 0, "packets_in": d["packets"] if d else 0,
            "bytes_out": u["bytes"] if u else 0, "bytes_in": d["bytes"] if d else 0,
            "udp_encap": any(x["udp_encap"] for x in (u, d) if x),
            "seq": {"out": [u["seq_first"], u["seq_last"]] if u else None,
                    "in": [d["seq_first"], d["seq_last"]] if d else None},
            "geometry": geo, "first_packets": (u["idx"] if u else []) + (d["idx"] if d else []),
        })

    # ---------- lifetimes
    def intervals(ts: list[float]) -> list[float]:
        ts = sorted(ts)
        return [b - a for a, b in zip(ts, ts[1:])]

    auth_ok = [p.ts for p, m in root.exchanges(35) if m.response] if root and root.version == 2 else []
    est_times = auth_ok[:1]
    child_rk = [e["t"] for e in child_events if e["kind"] in ("child_rekey",)]
    if root and root.version == 1:
        child_rk = [e["t"] for e in child_events if e["kind"] == "quick_mode"]
        est_times = []
    child_iv = intervals(est_times + child_rk)
    # anchor on the first IKE SA only when it was born inside the capture; a capture that starts
    # mid-session sees the old SA's end, not its start
    anchor = [root.first_ts] if root and sa_list and sa_list[0] is root else []
    ike_iv = intervals(anchor + ike_rekey_times)
    t_first = min([s.first_ts for s in sa_list] + [c["first_ts"] for c in child_out] or [0])
    t_last = max([s.last_ts for s in sa_list] + [c["last_ts"] for c in child_out] or [0])
    observed = t_last - t_first
    lifetimes = {
        "child_rekey_interval": round(statistics.median(child_iv)) if child_iv else None,
        "child_rekeys": len(child_rk) - (1 if root and root.version == 1 and child_rk else 0),
        "ike_rekey_interval": round(statistics.median(ike_iv)) if ike_iv else None,
        "ike_rekeys": len(ike_rekey_times),
        "observed_seconds": round(observed),
        "child_rekey_range": [round(min(child_iv)), round(max(child_iv))] if child_iv else None,
        "ike_rekey_range": [round(min(ike_iv)), round(max(ike_iv))] if ike_iv else None,
        "child_rekey_times": [round(t - t_first, 2) for t in child_rk],
        "ike_rekey_times": [round(t - t_first, 2) for t in ike_rekey_times],
        "child_lower_bound": None, "ike_lower_bound": None,
        "v1_proposed_ike_lifetime": (root.to_dict()["v1_lifetime"].get("seconds") if root and root.version == 1 else None),
    }
    # without a measured interval the lifetime is at least the longest time one SA was seen alive
    if not child_iv:
        lifetimes["child_lower_bound"] = round(max([c["last_ts"] - c["first_ts"] for c in child_out] or [observed]))
    if not ike_iv:
        lifetimes["ike_lower_bound"] = round(max([s.last_ts - s.first_ts for s in sa_list] or [observed]))

    # ---------- PFS summary
    rekey_ev = [e for e in pfs_evidence if not e.get("initial")] or pfs_evidence
    if rekey_ev:
        yes = [e for e in rekey_ev if e["pfs"]]
        pfs = {"status": "enabled" if len(yes) > len(rekey_ev) / 2 else "disabled",
               "evidence": len(rekey_ev),
               "group": max({e["pfs_group"] for e in yes}, key=lambda g: sum(e["pfs_group"] == g for e in yes)) if yes else None,
               "group_id": yes[0]["pfs_group_id"] if yes else None,
               "confidence": min((e["confidence"] for e in rekey_ev), key=["High", "Medium", "Low"].index)}
        if root and root.version == 2 and not [e for e in pfs_evidence if e["kind"] == "child_rekey"]:
            pfs["status"] = "unknown"
    else:
        pfs = {"status": "unknown", "evidence": 0, "group": None, "group_id": None, "confidence": "None"}

    # ---------- DPD cadence (empty INFORMATIONAL / v1 informational)
    info_ts = []
    for sa in sa_list:
        for p, m in sa.msgs:
            if (m.exchange == 37 and not m.response and m.sk_len <= 64) or (m.version == 1 and m.exchange == 5):
                info_ts.append(p.ts)
    info_ts.sort()
    info_ts = [t for i, t in enumerate(info_ts) if i == 0 or t - info_ts[i - 1] > 2]   # request/ack pairs
    dpd_iv = intervals(info_ts)
    sa_dicts = []
    for sa in sa_list:
        d = sa.to_dict()
        if getattr(sa, "inherited", False):
            d["chosen"] = dict(sa.chosen, names=crypto_names(sa.chosen))
            d["inherited_crypto"] = True
        sa_dicts.append(d)
    return {
        "id": f"T{n}", "peers": list(key), "initiator": initiator, "responder": responder,
        "version": version, "first_ts": t_first, "last_ts": t_last,
        "ike_sas": sa_dicts, "child_sas": child_out, "rekey_events": child_events,
        "ike_crypto": dict(ike_crypto, names=crypto_names(ike_crypto)) if ike_crypto else None,
        "lifetimes": lifetimes, "pfs": pfs,
        "negotiated_child_sas": 1 + sum(e["kind"] in ("child_rekey",) for e in child_events)
        if version == 2 else max(1, sum(e["kind"] == "quick_mode" for e in child_events)),
        "dpd_interval": round(statistics.median(dpd_iv)) if len(dpd_iv) >= 2 else None,
        # NAT-T means ESP really is UDP-encapsulated (or ports were rewritten by a NAT); IKE merely
        # floating to 4500 is what strongSwan and others do even without a NAT, so it is not enough
        "nat_t": any(c["udp_encap"] for c in child_out) or any(d["nat_detected"] for d in sa_dicts),
        "ike_port_4500": any(d["nat_t"] for d in sa_dicts),
        "esp_packets": sum(c["packets"] for c in child_out), "esp_bytes": sum(c["bytes"] for c in child_out),
    }
