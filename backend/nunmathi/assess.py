"""Posture assessment: ZAP-style alerts (NM-1xx), grade and what-if twin."""
from __future__ import annotations

import copy
import math

from . import attack
from . import constants as C

RISK_ORDER = ["High", "Medium", "Low", "Informational"]
RISK_PENALTY = {"High": 25, "Medium": 10, "Low": 3, "Informational": 0}

WEAK_ENCR = {1: "DES-IV64", 2: "DES", 3: "3DES", 7: "Blowfish", 1002: "DES", 1003: "3DES"}
WEAK_PRF = {1: "HMAC-MD5"}
LEGACY_PRF = {2: "HMAC-SHA1"}

RULES = {
    "NM-100": ("IKEv1 in use", "IKEv1 is deprecated (RFC 9395). It lacks IKEv2's anti-DoS cookies by default, has "
               "complex modes and several known protocol weaknesses."),
    "NM-101": ("IKEv1 Aggressive Mode with pre-shared key", "The responder's HASH_R is sent before any encryption, "
               "which allows offline dictionary attacks on the PSK (ike-scan/psk-crack)."),
    "NM-102": ("Identity disclosed in cleartext", "The IKE identity is visible to any passive observer."),
    "NM-110": ("Weak IKE encryption algorithm", "The IKE SA is protected by a 64-bit block or deprecated cipher."),
    "NM-111": ("Weak or legacy IKE PRF/integrity", "MD5 is broken; SHA-1 is deprecated for new deployments."),
    "NM-112": ("Weak Diffie-Hellman group", "The key exchange provides less than 112 bits of classical security."),
    "NM-113": ("Weak algorithms offered in proposal", "Weak transforms are still offered; a misconfigured peer or an "
               "active attacker could steer negotiation towards them."),
    "NM-114": ("Key-exchange group renegotiation (INVALID_KE_PAYLOAD)", "The initiator guessed a group the responder "
               "does not accept; adds a round trip and reveals the responder's preferred group."),
    "NM-120": ("ESP-NULL: traffic is not encrypted", "Inner packets are visible on the wire; only integrity is provided."),
    "NM-121": ("Weak ESP cipher (64-bit block)", "64-bit block ciphers are vulnerable to birthday attacks "
               "(Sweet32) on long-lived SAs."),
    "NM-122": ("ESP integrity uses a truncated SHA-1/MD5 MAC", "Legacy integrity algorithm on ESP."),
    "NM-130": ("No Perfect Forward Secrecy on Child SA rekey", "Child SA keys are derived from the IKE SA key; "
               "compromise of the IKE SA exposes all Child SAs."),
    "NM-131": ("Long Child SA lifetime", "Long-lived keys increase the amount of data exposed per key."),
    "NM-132": ("Long IKE SA lifetime", "The IKE SA (and its authentication) is refreshed rarely."),
    "NM-150": ("Application traffic identifiable through encryption", "Packet sizes and timing reveal the application "
               "type despite encryption (traffic analysis)."),
    "NM-160": ("Half-open IKE flood observed", "Many IKE_SA_INIT requests without completion targeted the responder."),
    "NM-161": ("IKE fragmentation not negotiated", "Large IKE_AUTH messages (certificates, PQ keys) may be IP-fragmented "
               "and dropped by middleboxes."),
    "NM-162": ("NAT traversal in use", "ESP is UDP-encapsulated (port 4500), which indicates a NAT between the peers. IKE alone on port 4500 does not count."),
    "NM-170": ("Implementation fingerprint via Vendor ID", "Vendor ID payloads reveal the IPsec implementation."),
    "NM-171": ("Dead Peer Detection interval", "Observed liveness-check cadence."),
    "NM-180": ("Analysis coverage note", "Aspects that could only be bounded from this capture."),
}

REMEDIATION = {
    "NM-100": "Migrate to IKEv2 (strongSwan: version = 2 / libreswan: ikev2=insist).",
    "NM-101": "Disable Aggressive Mode; use IKEv2 with certificates or EAP. If PSK is unavoidable use >= 20 random characters.",
    "NM-102": "Use IKEv2 (identities are encrypted in IKE_AUTH) or Main Mode.",
    "NM-110": "Use AES-GCM-16 (256-bit) for IKE.",
    "NM-111": "Use PRF HMAC-SHA2-384 or higher.",
    "NM-112": "Use ECP-384, Curve25519 or MODP-3072+; add ML-KEM-768 (RFC 9370).",
    "NM-113": "Remove 3DES, SHA-1, MD5 and MODP <= 1536 from the proposal list.",
    "NM-114": "Make the initiator's first KE guess match the responder's preferred group.",
    "NM-120": "Configure an encryption transform for ESP (e.g. aes256gcm16).",
    "NM-121": "Use AES-GCM-16 or ChaCha20-Poly1305 for ESP.",
    "NM-122": "Use AEAD (AES-GCM) or HMAC-SHA2-256-128 integrity.",
    "NM-130": "Add a DH group to esp_proposals (e.g. aes256gcm16-ecp384) so every rekey runs a fresh key exchange.",
    "NM-131": "Set rekey_time <= 1 h for Child SAs (life_time ~ 1.1 x rekey_time).",
    "NM-132": "Set IKE rekey_time <= 8 h (strongSwan default 4 h).",
    "NM-150": "Enable TFC padding (strongSwan: tfc_padding = mtu) or a traffic-shaping overlay for sensitive flows.",
    "NM-160": "Enable IKEv2 cookies / rate limiting (strongSwan: charon.cookie_threshold, block_threshold).",
    "NM-161": "Enable IKEv2 fragmentation (RFC 7383): fragmentation = yes.",
    "NM-162": "None required; ensure UDP 4500 keepalives are within NAT timeouts.",
    "NM-170": "Suppress vendor ID payloads (strongSwan: send_vendor_id = no).",
    "NM-171": "Keep DPD enabled (30-120 s for remote access, <= 300 s for site-to-site).",
    "NM-180": "Capture a longer period to measure the bounded values.",
}

REFERENCES = {
    "NM-100": ["RFC 9395"], "NM-101": ["CVE-2002-1623", "RFC 2409 §5.4"], "NM-102": ["RFC 2409"],
    "NM-110": ["RFC 8221", "RFC 8247"], "NM-111": ["RFC 8247"], "NM-112": ["RFC 8247", "NIST SP 800-57"],
    "NM-113": ["RFC 8247"], "NM-114": ["RFC 7296 §1.2"], "NM-120": ["RFC 8221 §5"], "NM-121": ["CVE-2016-2183 (Sweet32)"],
    "NM-122": ["RFC 8221"], "NM-130": ["RFC 7296 §1.3.1"], "NM-131": ["NIST SP 800-77r1"], "NM-132": ["NIST SP 800-77r1"],
    "NM-150": ["RFC 4303 §2.7 (TFC)"],
    "NM-160": ["RFC 8019"], "NM-161": ["RFC 7383"], "NM-162": ["RFC 3948"], "NM-170": ["RFC 7296 §3.12"],
    "NM-171": ["RFC 3706", "RFC 7296 §2.4"], "NM-180": [],
}

# normative requirements each rule checks against (cited in the technical report)
STANDARDS = {
    "NM-100": ["RFC 9395: IKEv1 is deprecated", "NIST SP 800-77r1 §3: use IKEv2"],
    "NM-101": ["RFC 2409 §5.4 (Aggressive Mode)", "NIST SP 800-77r1: avoid Aggressive Mode with PSK"],
    "NM-102": ["RFC 7296 §1.2: identities protected inside SK"],
    "NM-110": ["RFC 8247 §2.1: ENCR_3DES MAY, DES MUST NOT", "CNSA 2.0: AES-256"],
    "NM-111": ["RFC 8247 §2.2: PRF_HMAC_MD5 MUST NOT, PRF_HMAC_SHA1 MUST-"],
    "NM-112": ["RFC 8247 §2.4: groups 1/2/5 MUST NOT/SHOULD NOT", "NIST SP 800-57 Pt1 Rev5: >= 112-bit strength"],
    "NM-113": ["RFC 8247 §2: MUST NOT algorithms should not be configured"],
    "NM-114": ["RFC 7296 §1.2 / §3.10.1: INVALID_KE_PAYLOAD"],
    "NM-120": ["RFC 8221 §5: ENCR_NULL only where confidentiality is not needed"],
    "NM-121": ["RFC 8221 §5: ENCR_3DES SHOULD NOT", "CVE-2016-2183 (Sweet32)"],
    "NM-122": ["RFC 8221 §6: AUTH_HMAC_MD5_96 MUST NOT, AUTH_HMAC_SHA1_96 MUST-"],
    "NM-130": ["RFC 7296 §1.3.1: KE in CREATE_CHILD_SA for PFS", "NIST SP 800-77r1 §5: enable PFS"],
    "NM-131": ["NIST SP 800-77r1 Table 6: Child SA lifetime <= 8 h"],
    "NM-132": ["NIST SP 800-77r1 Table 6: IKE SA lifetime <= 24 h"],
    "NM-150": ["RFC 4303 §2.7: Traffic Flow Confidentiality padding"],
    "NM-160": ["RFC 8019: protecting IKEv2 against DoS", "RFC 7296 §2.6: COOKIE"],
    "NM-161": ["RFC 7383: IKEv2 message fragmentation"],
    "NM-162": ["RFC 3948: UDP encapsulation of ESP"],
    "NM-170": ["RFC 7296 §3.12: Vendor ID payload is optional"],
    "NM-171": ["RFC 7296 §2.4: liveness checks", "RFC 3706 (IKEv1 DPD)"],
}


# ------------------------------------------------------------------ posture extraction
def _ranked_geometries(t: dict) -> list[dict]:
    """Child SA geometries, best supported first; ambiguous ones only after every resolved one."""
    rank = {"High": 3, "Medium": 2, "Low": 1}
    return sorted((c["geometry"] for c in t["child_sas"] if c["geometry"].get("best")),
                  key=lambda g: (g["best"]["family"] != "AMBIGUOUS", rank.get(g["confidence"], 0),
                                 g["distinct_lengths"]), reverse=True)


def tunnel_geometry(t: dict) -> dict | None:
    geos = _ranked_geometries(t)
    return geos[0]["best"] if geos else None


def posture_from_tunnel(t: dict) -> dict:
    root = next((s for s in t["ike_sas"] if s["origin"] != "rekey"), t["ike_sas"][0] if t["ike_sas"] else None)
    ic = t.get("ike_crypto") or {}
    geos = _ranked_geometries(t)
    esp = geos[0]["best"] if geos else None
    offered_weak = []
    if root:
        for o in root["offered"]:
            if o.get("encr") in WEAK_ENCR:
                offered_weak.append(C.ENCR.get(o["encr"], WEAK_ENCR.get(o["encr"])))
            if o.get("group") is not None and C.KE_STRENGTH.get(o["group"], 999) < 112:
                offered_weak.append(C.KE.get(o["group"]))
            if o.get("prf") in WEAK_PRF or o.get("prf") in LEGACY_PRF:
                offered_weak.append(C.PRF.get(o["prf"]))
    auth_frag = any(s["exchanges"].get("IKE_AUTH", 0) > 2 for s in t["ike_sas"])
    lt = t["lifetimes"]
    vids = []
    for s in t["ike_sas"]:
        vids += [v["name"] for v in s["vendor_ids"]["initiator"] + s["vendor_ids"]["responder"]]
    return {
        "version": t["version"],
        "aggressive": bool(root and root["aggressive"]),
        "v1_auth": None if not root else ("psk" if root.get("v1_auth") == 1 else root.get("v1_auth")),
        "identities": root["identities"] if root else [],
        "ike_encr": ic.get("encr"), "ike_keylen": ic.get("keylen"), "ike_prf": ic.get("prf"), "ike_integ": ic.get("integ"),
        "ike_group": ic.get("group"), "addke": list(ic.get("addke") or []),
        "offered_weak": sorted(set(x for x in offered_weak if x)),
        "invalid_ke": root.get("invalid_ke_wanted") if root else None,
        "esp_family": esp["family"] if esp else None, "esp_key": esp["key"] if esp else None,
        "esp_label": esp["label"] if esp else None, "esp_icv": esp.get("icv") if esp else None,
        "esp_block": esp.get("block") if esp else None,
        "esp_members": esp.get("members", []) if esp else [],
        "esp_confidence": geos[0]["confidence"] if geos else None,
        "pfs": t["pfs"]["status"], "pfs_group": t["pfs"].get("group_id"), "pfs_confidence": t["pfs"]["confidence"],
        "child_life": lt["child_rekey_interval"] or lt["child_lower_bound"],
        "child_life_bound": lt["child_rekey_interval"] is None,
        "ike_life": lt["ike_rekey_interval"] or lt["ike_lower_bound"],
        "ike_life_bound": lt["ike_rekey_interval"] is None,
        "v1_proposed_ike_lifetime": lt.get("v1_proposed_ike_lifetime"),
        "fragmentation": bool(root and root["fragmentation"]["initiator"] and root["fragmentation"]["responder"]),
        "auth_fragmented": auth_frag,
        "nat_t": t["nat_t"], "dpd": t["dpd_interval"],
        "vendor_ids": sorted(set(v for v in vids if v and v != "unknown")),
        "mei": (t.get("traffic") or {}).get("summary", {}).get("mei_mean"),
        "classes": {k: v for k, v in (t.get("traffic") or {}).get("summary", {}).get("class_windows", {}).items() if v},
        "esp_bytes": t["esp_bytes"], "esp_packets": t["esp_packets"],
        "observed_seconds": lt["observed_seconds"], "tfc_padding": _tfc_padded(t),
        "mode": _tunnel_mode(t),
    }


def _tfc_padded(t: dict) -> bool:
    """TFC padding to the MTU leaves (almost) every ESP packet of an SA at one length."""
    tot = dom = 0
    for c in t["child_sas"]:
        h = c["geometry"].get("length_hist") or {}
        cnt = [a + b for a, b in zip(h.get("out", []), h.get("in", []))]
        if cnt:
            tot += sum(cnt)
            dom += max(cnt)
    return tot >= 50 and dom / tot >= 0.9


def _tunnel_mode(t: dict) -> dict | None:
    rank = {"High": 3, "Medium": 2, "Low": 1, "None": 0}
    modes = [c["geometry"].get("mode") for c in t["child_sas"] if c["geometry"].get("mode")]
    return max(modes, key=lambda m: rank.get(m["confidence"], 0)) if modes else None


# ------------------------------------------------------------------ rules
def _alert(rid: str, risk: str, confidence: str, evidence: str, params: dict | None = None, tunnel: str = "") -> dict:
    name, desc = RULES[rid]
    return {"id": rid, "name": name, "risk": risk, "confidence": confidence, "description": desc,
            "evidence": evidence, "solution": REMEDIATION[rid], "references": REFERENCES[rid],
            "params": params or {}, "tunnel": tunnel, "standards": STANDARDS.get(rid, []),
            "attack": attack.techniques_for(rid)}


def evaluate(p: dict, tunnel_id: str = "", half_open: list | None = None) -> list[dict]:
    A = []
    tid = tunnel_id
    if p["version"] == 1:
        A.append(_alert("NM-100", "Medium", "Confirmed", "IKE major version 1 observed.", tunnel=tid))
        if p["aggressive"]:
            risk = "High" if p.get("v1_auth") == "psk" else "Medium"
            A.append(_alert("NM-101", risk, "Confirmed", f"Aggressive Mode exchange, authentication={p.get('v1_auth')}.",
                            tunnel=tid))
    if p["identities"]:
        A.append(_alert("NM-102", "Medium", "Confirmed", "Identity: " + ", ".join(p["identities"]), tunnel=tid))
    e = p.get("ike_encr")
    if e in WEAK_ENCR:
        A.append(_alert("NM-110", "High" if e in (1, 2, 1002) else "Medium", "Confirmed",
                        f"IKE encryption: {C.ENCR.get(e, WEAK_ENCR[e])}", tunnel=tid))
    if p.get("ike_prf") in WEAK_PRF:
        A.append(_alert("NM-111", "High", "Confirmed", f"IKE PRF {C.PRF[p['ike_prf']]}", tunnel=tid))
    elif p.get("ike_prf") in LEGACY_PRF or p.get("ike_integ") in (1, 2):
        A.append(_alert("NM-111", "Low", "Confirmed", f"IKE PRF {C.PRF.get(p.get('ike_prf'))}, integrity "
                        f"{C.INTEG.get(p.get('ike_integ'))}", tunnel=tid))
    g = p.get("ike_group")
    if g is not None:
        s = C.KE_STRENGTH.get(g, 0)
        if s < 100:
            A.append(_alert("NM-112", "High", "Confirmed", f"{C.KE.get(g)} (~{s}-bit)", tunnel=tid))
        elif s < 112:
            A.append(_alert("NM-112", "Medium", "Confirmed", f"{C.KE.get(g)} (~{s}-bit)", tunnel=tid))
    if p["offered_weak"]:
        A.append(_alert("NM-113", "Low", "Confirmed", "Offered: " + ", ".join(p["offered_weak"]), tunnel=tid))
    if p.get("invalid_ke"):
        A.append(_alert("NM-114", "Informational", "Confirmed",
                        f"Responder requested {C.KE.get(p['invalid_ke'], p['invalid_ke'])}.", tunnel=tid))
    fam = p.get("esp_family")
    if fam == "NULL":
        A.append(_alert("NM-120", "High", "Confirmed", "Cleartext inner IPv4 headers after the ESP header "
                        f"(ICV {p.get('esp_icv')} bytes).", tunnel=tid))
    elif fam == "CBC64":
        A.append(_alert("NM-121", "Medium", "Firm" if p.get("esp_confidence") == "High" else "Tentative",
                        f"ESP geometry: {p.get('esp_label')} "
                        f"(8-byte block, candidates: {', '.join(p['esp_members'][:3])}).", tunnel=tid))
    if p.get("esp_key") in ("cbc128-icv96", "cbc64-icv96") or (fam == "NULL" and p.get("esp_icv") == 12):
        A.append(_alert("NM-122", "Low", "Tentative", "12-byte ICV: HMAC-SHA1-96, HMAC-MD5-96 or AES-XCBC-96.",
                        tunnel=tid))
    if p["pfs"] == "disabled":
        A.append(_alert("NM-130", "Medium", "Firm" if p["pfs_confidence"] == "High" else "Tentative",
                        "Rekey messages are too small to carry a KE payload.", tunnel=tid))
    cl = p.get("child_life")
    if cl:
        if cl > 86400:
            A.append(_alert("NM-131", "Medium", "Firm", f"Child SA rekey every {_dur(cl)}.", tunnel=tid))
        elif cl > 8 * 3600 and not p["child_life_bound"]:
            A.append(_alert("NM-131", "Low", "Firm", f"Child SA rekey every {_dur(cl)}.", tunnel=tid))
        elif cl > 8 * 3600:
            A.append(_alert("NM-131", "Low", "Tentative", f"No Child SA rekey within {_dur(cl)} of capture.", tunnel=tid))
    il = p.get("ike_life")
    v1l = p.get("v1_proposed_ike_lifetime")
    if (il and il > 86400 and not p["ike_life_bound"]) or (v1l and v1l >= 86400):
        ev = f"IKE SA rekey every {_dur(il)}." if not p["ike_life_bound"] else f"Proposed IKE lifetime {_dur(v1l)}."
        A.append(_alert("NM-132", "Low", "Firm", ev, tunnel=tid))
    if p.get("mei") is not None and not p.get("tfc_padding"):
        if p["mei"] >= 0.8:
            A.append(_alert("NM-150", "Low", "Firm", f"Mean Metadata Exposure Index {p['mei']:.2f} "
                            f"(classes: {', '.join(f'{k} {v}' for k, v in p['classes'].items())}).", tunnel=tid))
        elif p["mei"] >= 0.5:
            A.append(_alert("NM-150", "Informational", "Tentative", f"Mean Metadata Exposure Index {p['mei']:.2f}.", tunnel=tid))
    if p["version"] == 2 and not p["fragmentation"]:
        A.append(_alert("NM-161", "Low" if (p["auth_fragmented"] or p["addke"]) else "Informational", "Confirmed",
                        "IKEV2_FRAGMENTATION_SUPPORTED not exchanged by both peers.", tunnel=tid))
    if p["nat_t"]:
        A.append(_alert("NM-162", "Informational", "Confirmed", "ESP is UDP-encapsulated (RFC 3948) or a NAT rewrote the IKE ports.", tunnel=tid))
    if p["vendor_ids"]:
        A.append(_alert("NM-170", "Low", "Confirmed", "Vendor IDs: " + ", ".join(p["vendor_ids"]), tunnel=tid))
    A.append(_alert("NM-171", "Informational", "Firm" if p["dpd"] else "Tentative",
                    f"DPD every ~{p['dpd']} s." if p["dpd"] else "No periodic DPD observed.", tunnel=tid))
    bounds = []
    if p["child_life_bound"]:
        bounds.append(f"Child SA lifetime > {_dur(p['child_life'])}")
    if p["ike_life_bound"]:
        bounds.append(f"IKE SA lifetime > {_dur(p['ike_life'])}")
    if p["pfs"] == "unknown":
        bounds.append("PFS unknown (no Child SA rekey observed)")
    if bounds:
        A.append(_alert("NM-180", "Informational", "Confirmed", "; ".join(bounds) + ".", tunnel=tid))
    for a in evaluate_half_open(half_open or []):
        a["tunnel"] = tid
        A.append(a)
    A.sort(key=lambda a: (RISK_ORDER.index(a["risk"]), a["id"]))
    return A


def evaluate_half_open(half_open: list) -> list[dict]:
    out = []
    for h in half_open:
        risk = "High" if h["attempts"] >= 100 else "Medium"
        out.append(_alert("NM-160", risk, "Confirmed",
                          f"{h['attempts']} half-open IKE_SA_INIT to {h['responder']} from {h['distinct_sources']} "
                          f"sources (~{h['rate_per_s']}/s); COOKIE challenges: {h['cookies']}."))
    return out


def grade(alerts: list[dict]) -> dict:
    score = 100 - sum(RISK_PENALTY[a["risk"]] for a in alerts)
    score = max(0, score)
    highs = sum(a["risk"] == "High" for a in alerts)
    letter = "A+" if score >= 97 else "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 \
        else "D" if score >= 40 else "F"
    if highs and letter in ("A+", "A", "B"):
        letter = "C"
    if highs >= 3:
        letter = "F"
    counts = {r: sum(a["risk"] == r for a in alerts) for r in RISK_ORDER}
    return {"score": score, "letter": letter, "counts": counts, "risk_score": 100 - score}


# ------------------------------------------------------------------ what-if twin
CHANGES = {
    "ikev2": "Migrate to IKEv2",
    "strong_ike": "IKE: AES-256-GCM / PRF-SHA384 / ECP-384",
    "pq_hybrid": "Add ML-KEM-768 hybrid key exchange (RFC 9370)",
    "pfs": "Enable PFS on Child SAs (ECP-384)",
    "aead_esp": "ESP: AES-256-GCM-16",
    "child_1h": "Child SA rekey every 1 h",
    "ike_8h": "IKE SA rekey every 8 h",
    "fragmentation": "Enable IKEv2 fragmentation",
    "tfc_padding": "Enable TFC padding (pad to MTU)",
    "hide_vid": "Stop sending Vendor IDs",
}


def apply_changes(p: dict, changes: list[str]) -> dict:
    q = copy.deepcopy(p)
    for c in changes:
        if c == "ikev2":
            q.update(version=2, aggressive=False, v1_auth=None, identities=[], v1_proposed_ike_lifetime=None)
        elif c == "strong_ike":
            q.update(ike_encr=20, ike_keylen=256, ike_prf=6, ike_integ=0, ike_group=20, offered_weak=[], invalid_ke=None)
        elif c == "pq_hybrid":
            q["addke"] = [36]
        elif c == "pfs":
            q.update(pfs="enabled", pfs_group=20, pfs_confidence="High")
        elif c == "aead_esp":
            q.update(esp_family="AEAD", esp_key="stream", esp_label="AES-256-GCM-16", esp_icv=16, esp_block=4,
                     esp_members=["AES-GCM-16"])
        elif c == "child_1h":
            q.update(child_life=3600, child_life_bound=False)
        elif c == "ike_8h":
            q.update(ike_life=28800, ike_life_bound=False, v1_proposed_ike_lifetime=None)
        elif c == "fragmentation":
            q["fragmentation"] = True
        elif c == "tfc_padding":
            q["tfc_padding"] = True
        elif c == "hide_vid":
            q["vendor_ids"] = []
    return q


def cost_of(p: dict, q: dict, changes: list[str], tunnel: dict | None) -> dict:
    """Rough operational cost of a change set, from the observed traffic."""
    pk = max(1, p.get("esp_packets") or 0)
    by = p.get("esp_bytes") or 0
    secs = max(1, p.get("observed_seconds") or 1)

    def ovh(fam, icv, block):
        iv = {"AEAD": 8, "CBC": 16, "CBC64": 8, "NULL": 0}.get(fam, 8)
        return 8 + iv + (icv or 16) + (block or 4) / 2
    d_esp = (ovh(q.get("esp_family"), q.get("esp_icv"), q.get("esp_block"))
             - ovh(p.get("esp_family"), p.get("esp_icv"), p.get("esp_block"))) * pk
    tfc = 0
    if "tfc_padding" in changes and tunnel:
        mean_len = by / pk
        tfc = max(0, (1400 - mean_len)) * pk
    child_rekeys = secs / q["child_life"] if q.get("child_life") else 0
    old_child_rekeys = secs / p["child_life"] if p.get("child_life") and not p.get("child_life_bound") else 0
    ke_bytes = (C.KE_SIZE.get(q.get("pfs_group"), 0) * 2 if q.get("pfs") == "enabled" else 0)
    pq_bytes = (1184 + 1088) if q.get("addke") else 0
    rekey_bytes = child_rekeys * (400 + ke_bytes + pq_bytes) - old_child_rekeys * 400
    extra = d_esp + tfc + max(0, rekey_bytes)
    return {"extra_bytes": int(extra), "extra_pct": round(100 * extra / max(1, by), 2),
            "extra_bytes_per_hour": int(extra * 3600 / secs),
            "rekeys_per_day": round(86400 / q["child_life"], 1) if q.get("child_life") else None,
            "handshake_bytes": int(2 * (C.KE_SIZE.get(q.get("ike_group"), 256)) + pq_bytes + 1400)}


def what_if(p: dict, changes: list[str], tunnel_id: str = "", tunnel: dict | None = None) -> dict:
    base_alerts = evaluate(p, tunnel_id)
    q = apply_changes(p, changes)
    new_alerts = evaluate(q, tunnel_id)
    return {"changes": changes, "labels": [CHANGES[c] for c in changes if c in CHANGES],
            "before": {"grade": grade(base_alerts), "alerts": [a["id"] for a in base_alerts]},
            "after": {"grade": grade(new_alerts), "alerts": [a["id"] for a in new_alerts],
                      "posture": q},
            "resolved": sorted({a["id"] for a in base_alerts} - {a["id"] for a in new_alerts}),
            "cost": cost_of(p, q, changes, tunnel),
            "config": config_snippets(q)}


def recommended_changes(p: dict) -> list[str]:
    ids = {a["id"] for a in evaluate(p)}
    out = []
    if "NM-100" in ids or "NM-101" in ids or "NM-102" in ids:
        out.append("ikev2")
    if ids & {"NM-110", "NM-111", "NM-112", "NM-113", "NM-114"}:
        out.append("strong_ike")
    if "NM-130" in ids or p.get("pfs") == "unknown":
        out.append("pfs")
    if ids & {"NM-120", "NM-121", "NM-122"}:
        out.append("aead_esp")
    if "NM-131" in ids:
        out.append("child_1h")
    if "NM-132" in ids:
        out.append("ike_8h")
    if ("NM-161" in ids and (p.get("addke") or p.get("auth_fragmented"))) or "ikev2" in out:
        out.append("fragmentation")        # an IKEv1 -> IKEv2 migration should enable RFC 7383 from day one
    if "NM-170" in ids:
        out.append("hide_vid")
    return out


# ------------------------------------------------------------------ config snippets
_SW_ENCR = {20: "aes{k}gcm16", 19: "aes{k}gcm12", 18: "aes{k}gcm8", 28: "chacha20poly1305", 12: "aes{k}", 3: "3des",
            13: "aes{k}ctr", 11: "null"}
_SW_PRF = {1: "prfmd5", 2: "prfsha1", 5: "prfsha256", 6: "prfsha384", 7: "prfsha512"}
_SW_GROUP = {2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 19: "ecp256",
             20: "ecp384", 21: "ecp521", 31: "curve25519", 32: "curve448", 35: "mlkem512", 36: "mlkem768",
             37: "mlkem1024"}
_LS_GROUP = {14: "modp2048", 15: "modp3072", 19: "dh19", 20: "dh20", 21: "dh21", 31: "dh31", 2: "modp1024", 5: "modp1536"}


def _sw_encr(e, k):
    return _SW_ENCR.get(e, "aes256gcm16").format(k=k or 256)


def config_snippets(q: dict) -> dict:
    enc = _sw_encr(q.get("ike_encr") or 20, q.get("ike_keylen") or 256)
    prf = _SW_PRF.get(q.get("ike_prf") or 6, "prfsha384")
    grp = _SW_GROUP.get(q.get("ike_group") or 20, "ecp384")
    ke = "".join(f"-ke{i + 1}_{_SW_GROUP.get(g, 'mlkem768')}" for i, g in enumerate(q.get("addke") or []))
    ike_prop = f"{enc}-{prf}-{grp}{ke}"
    esp_enc = {"AEAD": "aes256gcm16", "CBC": "aes256-sha256", "CBC64": "3des-sha1", "NULL": "null-sha256"}.get(
        q.get("esp_family") or "AEAD", "aes256gcm16")
    esp_prop = esp_enc + (f"-{_SW_GROUP.get(q.get('pfs_group'), 'ecp384')}{ke}" if q.get("pfs") == "enabled" else "")
    child = int(q.get("child_life") or 3600)
    ikel = int(q.get("ike_life") or 14400)
    sw = f"""connections {{
    nunmathi-tunnel {{
        version = {q.get('version') or 2}
        proposals = {ike_prop}
        rekey_time = {_dur_sw(ikel)}
        fragmentation = {'yes' if q.get('fragmentation') else 'no'}
        send_vendor_id = {'no' if not q.get('vendor_ids') else 'yes'}
        dpd_delay = {q.get('dpd') or 30}s
        local {{ auth = pubkey }}
        remote {{ auth = pubkey }}
        children {{
            net {{
                esp_proposals = {esp_prop}
                rekey_time = {_dur_sw(child)}
                life_time = {_dur_sw(int(child * 1.1))}{chr(10) + '                tfc_padding = mtu' if q.get('tfc_padding') else ''}
            }}
        }}
    }}
}}"""
    ls_ike = f"aes_gcm256-sha2_384;{_LS_GROUP.get(q.get('ike_group'), 'dh20')}" if (q.get('ike_encr') or 20) == 20 else \
        f"aes{q.get('ike_keylen') or 256}-sha2_256;{_LS_GROUP.get(q.get('ike_group'), 'modp2048')}"
    if q.get("addke"):
        ls_ike += "+mlkem768"
    ls = f"""conn nunmathi-tunnel
    ikev2={'insist' if (q.get('version') or 2) == 2 else 'no'}
    ike={ls_ike}
    esp={'aes_gcm256' if (q.get('esp_family') or 'AEAD') == 'AEAD' else 'aes256-sha2_256'}
    pfs={'yes' if q.get('pfs') == 'enabled' else 'no'}
    ikelifetime={ikel}s
    salifetime={child}s
    fragmentation={'yes' if q.get('fragmentation') else 'no'}
    dpddelay={q.get('dpd') or 30}
    authby=rsasig"""
    return {"strongswan": sw, "libreswan": ls, "cisco_ios": _cisco(q, child, ikel)}


_IOS_ENCR = {20: "aes-gcm-{k}", 19: "aes-gcm-{k}", 12: "aes-cbc-{k}", 3: "3des", 28: "aes-gcm-256"}
_IOS_PRF = {1: "md5", 2: "sha1", 5: "sha256", 6: "sha384", 7: "sha512"}


def _cisco(q: dict, child: int, ikel: int) -> str:
    if (q.get("version") or 2) != 2:
        return ("! IKEv1 is deprecated (RFC 9395); Nunmathi only emits IKEv2 configuration for Cisco IOS.\n"
                "! Apply the 'Migrate to IKEv2' change to get a snippet.")
    e = q.get("ike_encr") or 20
    enc = _IOS_ENCR.get(e, "aes-gcm-256").format(k=q.get("ike_keylen") or 256)
    prf = _IOS_PRF.get(q.get("ike_prf") or 6, "sha384")
    grp = q.get("ike_group") or 20
    aead = e in (18, 19, 20, 28)
    lines = ["crypto ikev2 proposal NUNMATHI-PROP",
             f" encryption {enc}",
             (f" prf {prf}" if aead else f" integrity {prf}"),
             f" group {grp}"]
    if q.get("addke"):
        lines.append(" ! ML-KEM additional key exchange (RFC 9370) is not available on classic IOS / IOS-XE;"
                     " keep it on the strongSwan/Libreswan side or use a PQ-capable platform.")
    lines += ["!", "crypto ikev2 policy NUNMATHI-POL", " proposal NUNMATHI-PROP", "!",
              "crypto ikev2 profile NUNMATHI-PROFILE",
              " match identity remote address 0.0.0.0",
              " authentication remote rsa-sig", " authentication local rsa-sig",
              " pki trustpoint NUNMATHI-TP",
              f" lifetime {min(86400, max(120, ikel))}",
              f" dpd {q.get('dpd') or 30} 5 periodic"]
    if not q.get("vendor_ids"):
        lines.append(" ! IOS sends a Cisco VID by default; 'no crypto ikev2 diagnose' does not remove it on all releases")
    lines += ["!"]
    if q.get("fragmentation"):
        lines += ["crypto ikev2 fragmentation mtu 1360", "!"]
    fam = q.get("esp_family") or "AEAD"
    ts = {"AEAD": "esp-gcm 256", "CBC": "esp-aes 256 esp-sha256-hmac", "CBC64": "esp-3des esp-sha-hmac",
          "NULL": "esp-null esp-sha256-hmac"}.get(fam, "esp-gcm 256")
    lines += [f"crypto ipsec transform-set NUNMATHI-TS {ts}", " mode tunnel", "!",
              "crypto ipsec profile NUNMATHI-IPSEC", " set transform-set NUNMATHI-TS",
              " set ikev2-profile NUNMATHI-PROFILE",
              f" set security-association lifetime seconds {min(86400, max(120, child))}"]
    if q.get("pfs") == "enabled":
        lines.append(f" set pfs group{q.get('pfs_group') or 20}")
    if q.get("tfc_padding"):
        lines.append(" ! TFC padding (RFC 4303 §2.7) is not configurable on IOS; shape traffic upstream instead.")
    lines += ["!", "interface Tunnel0", " tunnel mode ipsec ipv4", " tunnel protection ipsec profile NUNMATHI-IPSEC"]
    return "\n".join(lines)


def _dur(s) -> str:
    if s is None:
        return "?"
    s = float(s)
    if s >= 86400:
        return f"{s / 86400:.1f} d"
    if s >= 3600:
        return f"{s / 3600:.1f} h"
    if s >= 60:
        return f"{s / 60:.0f} min"
    return f"{s:.0f} s"


def _dur_sw(s: int) -> str:
    return f"{s // 3600}h" if s % 3600 == 0 else f"{math.ceil(s / 60)}m"


def _bytes(n) -> str:
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"
