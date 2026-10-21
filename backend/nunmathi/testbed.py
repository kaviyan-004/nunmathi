"""YAML testbed specs: describe a VPN topology, build it in IPsecForge, capture it, analyze it.

The testbed is simulated. IPsecForge emits wire-exact IKE/ESP packets for every tunnel in the spec
(cleartext IKE payloads are real structures; encrypted parts are random bytes of the exact length
the negotiated transforms produce), merges them into one capture and records the ground truth. No
real VPN daemon is started, so results measure what a passive observer would see from a
correctly implemented peer with that configuration.

Spec (all keys optional unless noted):

    testbed: 1
    name: hq-and-branches
    duration: 2h            # seconds or 30m / 2h / 1d
    seed: 7
    tunnels:                # required, 1..16
      - name: hq-branch1
        from_scenario: branch-office          # start from a built-in scenario
        initiator: 198.51.100.10
        responder: 203.0.113.1
        ike:
          version: 2
          proposal: aes256gcm16-prfsha384-ecp384-ke1_mlkem768   # strongSwan syntax
          lifetime: 8h
          fragmentation: true
        esp:
          proposal: aes256gcm16-ecp384        # a DH group here enables PFS
          lifetime: 1h
          tfc_padding: false
        auth: cert                            # cert | psk
        nat_t: false
        dpd: 30s
        vendor_ids: [strongswan]              # strongswan | cisco-unity | ms-nt5 | dpd | nat-t | hex
        traffic: {classes: [web, voip], windows: 10}
"""
from __future__ import annotations

import copy
import ipaddress
import os
import re

from .forge import scenarios as S
from .forge import traffic_models as TM
from .forge import wire as W
from .forge.generator import BASE_EPOCH, TunnelSim

MAX_TUNNELS = 16
MAX_DURATION = 3 * 86400

ENCR = {"aes128gcm16": (20, 128), "aes192gcm16": (20, 192), "aes256gcm16": (20, 256),
        "aes128gcm12": (19, 128), "aes256gcm12": (19, 256), "aes128gcm8": (18, 128), "aes256gcm8": (18, 256),
        "aes128": (12, 128), "aes192": (12, 192), "aes256": (12, 256), "aes": (12, 128),
        "aes128ctr": (13, 128), "aes256ctr": (13, 256),
        "3des": (3, None), "des": (2, None), "chacha20poly1305": (28, 256), "null": (11, None)}
AEAD = {18, 19, 20, 28}
INTEG = {"md5": 1, "sha1": 2, "aesxcbc": 5, "sha256": 12, "sha384": 13, "sha512": 14}
PRF = {"prfmd5": 1, "prfsha1": 2, "prfaesxcbc": 4, "prfsha256": 5, "prfsha384": 6, "prfsha512": 7}
GROUP = {"modp768": 1, "modp1024": 2, "modp1536": 5, "modp2048": 14, "modp3072": 15, "modp4096": 16,
         "modp6144": 17, "modp8192": 18, "ecp256": 19, "ecp384": 20, "ecp521": 21, "curve25519": 31,
         "x25519": 31, "curve448": 32, "x448": 32, "mlkem512": 35, "mlkem768": 36, "mlkem1024": 37}
VENDORS = {"strongswan": S.STRONGSWAN, "cisco-unity": S.CISCO_UNITY, "ms-nt5": S.MS_NT5, "dpd": S.DPD_V1,
           "nat-t": S.NATT_V1}

EXAMPLE = """# Nunmathi testbed spec: every tunnel is built and captured by IPsecForge
testbed: 1
name: hq-and-branches
duration: 2h
seed: 7
tunnels:
  - name: hq-to-branch1
    initiator: 198.51.100.10
    responder: 203.0.113.1
    ike:
      version: 2
      proposal: aes256gcm16-prfsha384-ecp384-ke1_mlkem768
      lifetime: 8h
      fragmentation: true
    esp:
      proposal: aes256gcm16-ecp384
      lifetime: 1h
    auth: cert
    dpd: 30s
    traffic: {classes: [web, voip, email], windows: 8}

  - name: legacy-branch2
    from_scenario: legacy-ikev1
    initiator: 192.0.2.77
    responder: 203.0.113.1

  - name: road-warrior
    initiator: 100.64.3.20
    responder: 203.0.113.1
    ike:
      proposal: aes128-sha256-prfsha256-modp2048
      lifetime: 4h
    esp:
      proposal: aes128-sha256
      lifetime: 30m
    nat_t: true
    vendor_ids: [ms-nt5]
    traffic: {classes: [video, chat], windows: 6}
"""


class SpecError(ValueError):
    pass


def _dur(v, where: str) -> int:
    if isinstance(v, (int, float)) and v > 0:
        return int(v)
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*", str(v))
    if not m:
        raise SpecError(f"{where}: '{v}' is not a duration (use seconds or 30m / 2h / 1d)")
    return int(float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)])


def _ip(v, where: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(v)))
    except ValueError as e:
        raise SpecError(f"{where}: '{v}' is not an IPv4 address") from e


def parse_proposal(text: str, where: str, esp: bool) -> dict:
    """strongSwan-style proposal string -> transform IDs."""
    out = {"encr": None, "keylen": None, "integ": None, "prf": None, "group": None, "addke": []}
    for tok in str(text).lower().replace(" ", "").split("-"):
        if not tok:
            continue
        m = re.fullmatch(r"ke(\d)_(\w+)", tok)
        if m:
            if m.group(2) not in GROUP:
                raise SpecError(f"{where}: unknown additional key exchange '{m.group(2)}'")
            out["addke"].append(GROUP[m.group(2)])
        elif tok in ENCR and out["encr"] is None:
            out["encr"], out["keylen"] = ENCR[tok]
        elif tok in INTEG:
            out["integ"] = INTEG[tok]
        elif tok in PRF:
            out["prf"] = PRF[tok]
        elif tok in GROUP:
            out["group"] = GROUP[tok]
        else:
            raise SpecError(f"{where}: unknown algorithm '{tok}'")
    if out["encr"] is None:
        raise SpecError(f"{where}: no encryption algorithm in '{text}'")
    if out["encr"] in AEAD:
        out["integ"] = 0
    elif out["integ"] is None:
        if out["encr"] == 11 or not esp:
            out["integ"] = 12
        else:
            raise SpecError(f"{where}: non-AEAD cipher needs an integrity algorithm (e.g. -sha256)")
    if not esp:
        if out["prf"] is None:
            out["prf"] = {0: 6, 2: 2, 12: 5, 13: 6, 14: 7, 1: 1}.get(out["integ"], 5)
        if out["group"] is None:
            raise SpecError(f"{where}: IKE proposal needs a key-exchange group (e.g. -ecp384)")
    return out


def _tunnel_profile(spec: dict, i: int, duration: int, seed: int) -> dict:
    where = f"tunnels[{i}]"
    if not isinstance(spec, dict):
        raise SpecError(f"{where}: must be a mapping")
    known = {"name", "from_scenario", "initiator", "responder", "ike", "esp", "auth", "nat_t", "dpd",
             "vendor_ids", "traffic", "half_open_flood"}
    extra = set(spec) - known
    if extra:
        raise SpecError(f"{where}: unknown key(s) {', '.join(sorted(extra))}")
    base = spec.get("from_scenario")
    if base:
        if base not in S.SCENARIOS:
            raise SpecError(f"{where}.from_scenario: unknown scenario '{base}' "
                            f"(choose from {', '.join(S.SCENARIOS)})")
        prof = copy.deepcopy(S.SCENARIOS[base])
        prof.pop("title", None)
        prof.pop("description", None)
    else:
        prof = copy.deepcopy(S.HARDENED)
        prof.update(addke=[], vendor_ids=[S.STRONGSWAN])
    prof["name"] = str(spec.get("name") or f"tunnel-{i + 1}")
    prof["initiator"] = _ip(spec.get("initiator", f"198.51.100.{10 + i}"), f"{where}.initiator")
    prof["responder"] = _ip(spec.get("responder", "203.0.113.1"), f"{where}.responder")
    if prof["initiator"] == prof["responder"]:
        raise SpecError(f"{where}: initiator and responder must differ")

    ike = spec.get("ike") or {}
    if not isinstance(ike, dict):
        raise SpecError(f"{where}.ike: must be a mapping")
    if "version" in ike:
        if ike["version"] not in (1, 2):
            raise SpecError(f"{where}.ike.version: must be 1 or 2")
        prof["ike_version"] = ike["version"]
        if ike["version"] == 1:
            prof.setdefault("v1_mode", "main")
            prof.setdefault("v1_auth", 1 if spec.get("auth", "psk") == "psk" else 3)
    if "proposal" in ike:
        pr = parse_proposal(ike["proposal"], f"{where}.ike.proposal", esp=False)
        prof.update(ike_encr=pr["encr"], ike_keylen=pr["keylen"], ike_prf=pr["prf"], ike_integ=pr["integ"],
                    ike_group=pr["group"], addke=pr["addke"])
        if pr["encr"] == 11:
            raise SpecError(f"{where}.ike.proposal: IKE cannot use NULL encryption")
    if "lifetime" in ike:
        prof["ike_lifetime"] = _dur(ike["lifetime"], f"{where}.ike.lifetime")
    if "fragmentation" in ike:
        prof["fragmentation"] = bool(ike["fragmentation"])
    if prof.get("ike_version", 2) == 1 and prof.get("addke"):
        raise SpecError(f"{where}: additional key exchanges (ML-KEM) require IKEv2")

    esp = spec.get("esp") or {}
    if not isinstance(esp, dict):
        raise SpecError(f"{where}.esp: must be a mapping")
    if "proposal" in esp:
        pr = parse_proposal(esp["proposal"], f"{where}.esp.proposal", esp=True)
        prof.update(esp_encr=pr["encr"], esp_keylen=pr["keylen"], esp_integ=pr["integ"], pfs_group=pr["group"])
    if "lifetime" in esp:
        prof["child_lifetime"] = _dur(esp["lifetime"], f"{where}.esp.lifetime")
    if "tfc_padding" in esp:
        prof["tfc_padding"] = bool(esp["tfc_padding"])

    if "auth" in spec:
        if spec["auth"] not in ("cert", "psk"):
            raise SpecError(f"{where}.auth: must be cert or psk")
        prof["auth"] = spec["auth"]
    if "nat_t" in spec:
        prof["natt"] = bool(spec["nat_t"])
    if "dpd" in spec:
        prof["dpd"] = _dur(spec["dpd"], f"{where}.dpd")
    if "vendor_ids" in spec:
        vids = []
        for v in spec["vendor_ids"] or []:
            v = str(v).lower()
            if v in VENDORS:
                vids.append(VENDORS[v])
            elif re.fullmatch(r"(?:[0-9a-f]{2}){8,32}", v):
                vids.append(v)
            else:
                raise SpecError(f"{where}.vendor_ids: '{v}' is neither a known vendor nor hex")
        prof["vendor_ids"] = vids
        prof.pop("responder_vendor_ids", None)
    tr = spec.get("traffic") or {}
    if tr:
        cls = tr.get("classes", TM.CLASSES)
        bad = [c for c in cls if c not in TM.CLASSES]
        if bad or not cls:
            raise SpecError(f"{where}.traffic.classes: choose from {', '.join(TM.CLASSES)}")
        prof["classes"] = list(cls)
        prof["active_windows"] = max(1, min(60, int(tr.get("windows", 10))))
    if "half_open_flood" in spec:
        prof["half_open_flood"] = max(0, min(5000, int(spec["half_open_flood"])))

    prof["duration"] = duration
    prof["seed"] = seed * 101 + i
    if prof["child_lifetime"] < 10 or prof["ike_lifetime"] < 10:
        raise SpecError(f"{where}: lifetimes must be at least 10 s")
    # avoid window layouts that cannot fit into short captures
    lo, hi = prof.get("window_len", (15, 30))
    prof["active_windows"] = max(1, min(prof.get("active_windows", 12), int((duration - 10) / (hi + 3))))
    return prof


def load(text_or_dict) -> dict:
    """Validate a YAML (or already parsed) spec; returns {name, duration, seed, tunnels: [profile, ...]}."""
    if isinstance(text_or_dict, (str, bytes)):
        import yaml
        try:
            spec = yaml.safe_load(text_or_dict)
        except yaml.YAMLError as e:
            raise SpecError(f"YAML: {e}") from e
    else:
        spec = text_or_dict
    if not isinstance(spec, dict):
        raise SpecError("spec must be a YAML mapping")
    extra = set(spec) - {"testbed", "name", "duration", "seed", "tunnels"}
    if extra:
        raise SpecError(f"unknown top-level key(s) {', '.join(sorted(extra))}")
    if spec.get("testbed", 1) != 1:
        raise SpecError("testbed: only version 1 is supported")
    duration = _dur(spec.get("duration", 3600), "duration")
    if not 120 <= duration <= MAX_DURATION:
        raise SpecError(f"duration must be between 2 min and {MAX_DURATION // 86400} days")
    seed = int(spec.get("seed", 1))
    tunnels = spec.get("tunnels")
    if not isinstance(tunnels, list) or not tunnels:
        raise SpecError("tunnels: at least one tunnel is required")
    if len(tunnels) > MAX_TUNNELS:
        raise SpecError(f"tunnels: at most {MAX_TUNNELS}")
    profs = [_tunnel_profile(t, i, duration, seed) for i, t in enumerate(tunnels)]
    pairs = [tuple(sorted((p["initiator"], p["responder"]))) for p in profs]
    dup = {p for p in pairs if pairs.count(p) > 1}
    if dup:
        raise SpecError(f"two tunnels between the same peers {sorted(dup)[0]}: give each tunnel its own addresses")
    return {"name": re.sub(r"[^\w.\-]+", "_", str(spec.get("name") or "testbed"))[:60], "duration": duration,
            "seed": seed, "tunnels": profs}


def build(spec: dict, pcap_path: str) -> dict:
    """Forge every tunnel of a validated spec into one merged capture; returns the ground truth."""
    frames, truth = [], []
    for prof in spec["tunnels"]:
        sim = TunnelSim(prof, prof["seed"])
        sim.run()
        frames += sim.frames
        truth.append({"name": prof["name"], "initiator": prof["initiator"], "responder": prof["responder"],
                      "class_windows": sim.truth["class_windows"], "child_sas": len(sim.truth["child_sas"]),
                      "esp_geometry": list(W.esp_geometry(prof["esp_encr"], prof.get("esp_integ", 0)))})
    frames.sort(key=lambda f: f[0])
    w = W.PcapWriter(pcap_path)
    for ts, fr in frames:
        w.write(BASE_EPOCH + ts, fr)
    w.close()
    return {"name": spec["name"], "frames": w.count, "tunnels": truth}


def summary(spec: dict) -> list[dict]:
    from . import constants as C
    out = []
    for p in spec["tunnels"]:
        out.append({"name": p["name"], "initiator": p["initiator"], "responder": p["responder"],
                    "ike_version": p.get("ike_version", 2),
                    "ike": f"{C.ENCR.get(p['ike_encr'])}{'_' + str(p['ike_keylen']) if p.get('ike_keylen') else ''} / "
                           f"{C.PRF.get(p.get('ike_prf'))} / {C.KE.get(p.get('ike_group'))}"
                           + "".join(f" + {C.KE.get(g)}" for g in p.get("addke") or []),
                    "esp": f"{C.ENCR.get(p['esp_encr'])}" + (f" / {C.INTEG.get(p.get('esp_integ'))}"
                                                            if p.get("esp_integ") else ""),
                    "pfs": C.KE.get(p.get("pfs_group")) if p.get("pfs_group") else None,
                    "ike_lifetime": p["ike_lifetime"], "child_lifetime": p["child_lifetime"],
                    "nat_t": bool(p.get("natt")), "tfc_padding": bool(p.get("tfc_padding"))})
    return out


def posture_to_spec(p: dict, t: dict, duration: int = 3600) -> dict:
    """Turn an observed posture (possibly with what-if changes applied) into a one-tunnel spec dict."""
    fam = p.get("esp_family") or "AEAD"
    icv = p.get("esp_icv") or 16
    esp_integ = {12: "sha1", 16: "sha256", 24: "sha384", 32: "sha512"}.get(icv, "sha256")
    esp = {"AEAD": "aes256gcm16", "CBC": f"aes256-{esp_integ}", "CBC64": f"3des-{esp_integ}",
           "NULL": f"null-{esp_integ}"}.get(fam, "aes256gcm16")
    inv = {v: k for k, v in GROUP.items() if k not in ("x25519", "x448")}
    if p.get("pfs") == "enabled":
        esp += "-" + inv.get(p.get("pfs_group") or 20, "ecp384")
    ie = p.get("ike_encr") or 20
    cands = [k for k, (e, kl) in ENCR.items() if e == ie and k != "aes"]
    ename = next((k for k in cands if ENCR[k][1] == (p.get("ike_keylen") or ENCR[k][1])), cands[0] if cands
                 else "aes256gcm16")
    ike = [ename]
    if ie not in AEAD:
        ike.append({1: "md5", 2: "sha1", 12: "sha256", 13: "sha384", 14: "sha512"}.get(p.get("ike_integ"), "sha256"))
    ike.append({1: "prfmd5", 2: "prfsha1", 4: "prfaesxcbc", 5: "prfsha256", 6: "prfsha384", 7: "prfsha512"}
               .get(p.get("ike_prf"), "prfsha384"))
    ike.append(inv.get(p.get("ike_group") or 20, "ecp384"))
    ike += [f"ke{i + 1}_{inv.get(g, 'mlkem768')}" for i, g in enumerate(p.get("addke") or [])]
    child = int(p.get("child_life") or 3600)
    ikel = int(p.get("ike_life") or 14400)
    # a twin must observe at least two Child SA rekeys to measure the lifetime and PFS
    duration = max(duration, min(MAX_DURATION, int(child * 2.6)), 600)
    classes = [c for c, n in (p.get("classes") or {}).items() if n] or ["web", "voip"]
    spec = {"name": f"twin-{t.get('id', 'T')}", "initiator": t.get("initiator") or "198.51.100.10",
            "responder": t.get("responder") or "203.0.113.1",
            "ike": {"version": p.get("version") or 2, "proposal": "-".join(ike), "lifetime": ikel,
                    "fragmentation": bool(p.get("fragmentation"))},
            "esp": {"proposal": esp, "lifetime": child, "tfc_padding": bool(p.get("tfc_padding"))},
            "auth": "psk" if p.get("v1_auth") == "psk" else "cert",
            "nat_t": bool(p.get("nat_t")), "dpd": p.get("dpd") or 60,
            "traffic": {"classes": classes, "windows": 10}}
    vids = [n for n in (p.get("vendor_ids") or [])]
    names = {"strongSwan": "strongswan", "Cisco Unity": "cisco-unity", "Dead Peer Detection v1.0": "dpd",
             "RFC 3947 NAT-T": "nat-t", "Microsoft Windows (MS NT5 ISAKMPOAKLEY)": "ms-nt5"}
    spec["vendor_ids"] = [names[v] for v in vids if v in names] or ([] if not vids else ["strongswan"])
    if p.get("version") == 1:
        spec["from_scenario"] = "legacy-ikev1" if p.get("aggressive") else None
        if not spec["from_scenario"]:
            del spec["from_scenario"]
    return {"testbed": 1, "name": spec["name"], "duration": duration, "seed": 5, "tunnels": [spec]}


def run_spec(spec: dict, out_dir: str) -> tuple[str, dict]:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{spec['name']}.pcap")
    return path, build(spec, path)
