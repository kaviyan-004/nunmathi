"""ESP crypto-geometry solver.

An ESP packet on the wire is  SPI(4) | Seq(4) | IV(iv) | E(inner | pad | padlen | nh) | ICV(icv)
where the encrypted part is padded to the cipher block size B (4 for stream/AEAD modes).
Hence every packet length L of one SA satisfies  L = 8 + iv + icv + k*B  with k*B >= inner+2.
That residue structure identifies the cipher family and the ICV length class without
decrypting anything. Hypotheses that the data cannot tell apart are reported together as
one equivalence class instead of guessing.
"""
from __future__ import annotations

import math
import struct

# (key, block, iv, icv, label, members, family, representative (encr, integ))
HYPOTHESES = [
    ("cbc128-icv96", 16, 16, 12, "128-bit block CBC + 96-bit ICV",
     ["AES-CBC + HMAC-SHA1-96", "AES-CBC + AES-XCBC-96", "AES-CBC + HMAC-MD5-96", "Camellia-CBC + HMAC-SHA1-96"],
     "CBC", (12, 2)),
    ("cbc128-icv128", 16, 16, 16, "128-bit block CBC + 128/256-bit ICV",
     ["AES-CBC + HMAC-SHA2-256-128", "AES-CBC + HMAC-SHA2-512-256"], "CBC", (12, 12)),
    ("cbc128-icv192", 16, 16, 24, "128-bit block CBC + 192-bit ICV", ["AES-CBC + HMAC-SHA2-384-192"], "CBC", (12, 13)),
    ("cbc64-icv96", 8, 8, 12, "64-bit block CBC + 96-bit ICV",
     ["3DES-CBC + HMAC-SHA1-96", "DES-CBC + HMAC-SHA1-96", "Blowfish-CBC + HMAC-SHA1-96", "3DES-CBC + HMAC-MD5-96"],
     "CBC64", (3, 2)),
    ("cbc64-icv128", 8, 8, 16, "64-bit block CBC + >=128-bit ICV",
     ["3DES-CBC + HMAC-SHA2-256-128", "3DES-CBC + HMAC-SHA2-384-192", "3DES-CBC + HMAC-SHA2-512-256"], "CBC64", (3, 12)),
    ("stream", 4, 8, 16, "AEAD / counter mode",
     ["AES-GCM-16", "AES-GCM-12", "AES-GCM-8", "ChaCha20-Poly1305", "AES-CCM", "AES-CTR + HMAC"], "AEAD", (20, 0)),
]

MIN_INNER = 20   # a tunnel-mode inner packet is at least an IPv4 header


def _null_check(payloads: list[bytes]) -> dict | None:
    """Detect ESP-NULL: a cleartext inner IPv4 header right after SPI/Seq."""
    hits, icvs = 0, []
    for p in payloads[:400]:
        if len(p) >= 28 and p[8] == 0x45:
            tot = struct.unpack("!H", p[10:12])[0]
            if 20 <= tot <= len(p) - 10:
                hits += 1
                padded = tot + 2 + (-(tot + 2)) % 4
                icvs.append(len(p) - 8 - padded)
    n = min(len(payloads), 400)
    if n and hits / n >= 0.8:
        icv = max(set(icvs), key=icvs.count)
        integ = {12: "HMAC-SHA1-96 / AES-XCBC-96", 16: "HMAC-SHA2-256-128", 24: "HMAC-SHA2-384-192",
                 32: "HMAC-SHA2-512-256", 0: "none"}.get(icv, f"{icv * 8}-bit ICV")
        return {"fraction": round(hits / n, 3), "icv": icv, "integrity": integ}
    return None


def solve(lengths: list[int], payloads: list[bytes] | None = None) -> dict:
    """Infer ESP cipher geometry from packet lengths (bytes from SPI to end of ICV)."""
    distinct = sorted(set(lengths))
    res = {"packets": len(lengths), "distinct_lengths": len(distinct), "consistent": [], "best": None,
           "esp_null": None, "confidence": "None", "p_spurious": None, "proof": []}
    if not lengths:
        return res
    if payloads:
        nul = _null_check(payloads)
        if nul:
            res["esp_null"] = nul
            res["best"] = {"key": "null", "label": "ESP-NULL (no confidentiality)", "family": "NULL",
                           "block": 4, "iv": 0, "icv": nul["icv"], "members": [f"NULL + {nul['integrity']}"],
                           "encr": 11, "integ": {12: 2, 16: 12, 24: 13, 32: 14}.get(nul["icv"], 0)}
            res["confidence"] = "High"
            res["p_spurious"] = 0.0
            res["proof"] = [{"hypothesis": "null", "verdict": "High", "label": "ESP-NULL",
                             "claim": "byte 8 of the ESP payload is 0x45 and bytes 10-11 give a valid IPv4 total length",
                             "reason": f"{nul['fraction'] * 100:.0f}% of sampled packets carry a cleartext inner "
                                       f"IPv4 header; trailing {nul['icv']} B are the ICV"}]
            return res
    lmin = distinct[0]
    proof = res["proof"] = []
    for key, block, iv, icv, label, members, family, rep in HYPOTHESES:
        r = (8 + iv + icv) % block
        bad = next((L for L in distinct if L % block != r), None)
        room = lmin - 8 - iv - icv
        step = {"hypothesis": key, "label": label, "block": block, "iv": iv, "icv": icv,
                "claim": f"L = 8 + {iv} + {icv} + k*{block}  =>  L mod {block} = {r}"}
        if bad is not None:
            step.update(verdict="rejected", reason=f"counterexample L={bad}: {bad} mod {block} = {bad % block} != {r}")
        elif room < MIN_INNER + 2:
            step.update(verdict="rejected", reason=f"smallest packet L={lmin} leaves {room} B of ciphertext, "
                                                   f"< {MIN_INNER + 2} B (IPv4 header + pad length + next header)")
        else:
            step.update(verdict="consistent", reason=f"all {len(distinct)} distinct lengths are = {r} (mod {block}); "
                                                     f"smallest packet leaves {room} B >= {MIN_INNER + 2} B")
        proof.append(step)
        if step["verdict"] == "consistent":
            res["consistent"].append({"key": key, "label": label, "block": block, "iv": iv, "icv": icv,
                                      "members": members, "family": family, "encr": rep[0], "integ": rep[1],
                                      "mdl_bits": round(len(lengths) * math.log2(block), 1)})
    if not res["consistent"]:
        res["best"] = {"key": "unknown", "label": "No standard geometry (TFC padding, IPComp or non-standard)",
                       "family": "UNKNOWN", "block": 1, "iv": None, "icv": None, "members": [],
                       "encr": None, "integ": None}
        res["confidence"] = "Low"
        return res
    top_block = max(h["block"] for h in res["consistent"])
    best = [h for h in res["consistent"] if h["block"] == top_block]
    # probability that a coarser true block produced this many distinct lengths all on one residue by chance
    if top_block > 4:
        p = 0.5 ** max(0, len(distinct) - 1)
    else:
        p = 0.0   # block 4 is the coarsest standard block; no finer structure is being claimed
    res["p_spurious"] = round(p, 6)
    proof.append({"hypothesis": "chance", "verdict": "bound",
                  "claim": f"P(all {len(distinct)} distinct lengths share one residue mod {top_block} | true block is "
                           f"{top_block // 2 if top_block > 4 else top_block})",
                  "reason": (f"each extra distinct length lands on the same residue with probability 1/2, "
                             f"so p = 0.5^{max(0, len(distinct) - 1)} = {p:.3g}") if top_block > 4 else
                  "block 4 is the coarsest standard granularity; nothing finer is claimed (p = 0)"})
    res["confidence"] = "High" if p < 0.001 and len(lengths) >= 20 else "Medium" if p < 0.05 else "Low"
    blocks = sorted({h["block"] for h in res["consistent"]})
    if len(blocks) > 1 and p >= 0.05:
        # too few distinct lengths to tell the block sizes apart: do not claim the coarser one
        fine = next(h for h in res["consistent"] if h["block"] == blocks[0])
        alts = []
        for b in blocks:
            lab = next(h["label"] for h in res["consistent"] if h["block"] == b)
            if lab not in alts:
                alts.append(lab)
        res["best"] = dict(fine, key="ambiguous", family="AMBIGUOUS", label="Ambiguous: " + " or ".join(alts),
                           members=[m for h in res["consistent"] for m in h["members"]], alternatives=alts)
        res["confidence"] = "Low"
    else:
        res["best"] = best[0]
    proof.append({"hypothesis": "conclusion", "verdict": res["confidence"],
                  "claim": res["best"]["label"],
                  "reason": "largest block size consistent with every length wins (a finer block is always "
                            "trivially consistent); members of the class cannot be told apart by length alone"})
    return res


def infer_mode(lengths: list[int], best: dict | None, esp_null: dict | None = None) -> dict:
    """Tunnel vs transport mode from the smallest ciphertext.

    In tunnel mode every inner packet carries its own IP header (>= 20 B IPv4, 40 B IPv6), so the
    smallest real packet (a TCP ACK) is >= 40 B inside the ESP payload; in transport mode the same
    ACK is 20 B. The upper bound on the smallest inner length decides the question when it is small.
    """
    if esp_null:
        return {"mode": "tunnel", "confidence": "High", "max_inner_min": None,
                "reason": "ESP-NULL payload starts with a cleartext IPv4 header (0x45)"}
    if not lengths or not best or best.get("iv") is None:
        return {"mode": "unknown", "confidence": "None", "max_inner_min": None,
                "reason": "no ESP geometry to bound the inner length"}
    lmin = min(lengths)
    mx = lmin - 8 - int(best["iv"]) - int(best["icv"]) - 2   # padding may be 0, so this is an upper bound
    if mx < 20:
        return {"mode": "transport", "confidence": "High", "max_inner_min": mx,
                "reason": f"smallest packet holds at most {mx} B of inner data, less than any IPv4 header"}
    if mx < 28:
        return {"mode": "transport", "confidence": "Medium", "max_inner_min": mx,
                "reason": f"smallest inner packet is at most {mx} B: too small for IPv4+UDP/ICMP (28 B)"}
    if mx < 40:
        return {"mode": "transport", "confidence": "Low", "max_inner_min": mx,
                "reason": f"smallest inner packet is at most {mx} B: below an IPv4 TCP ACK (40 B)"}
    small = sum(1 for L in lengths if L - 8 - int(best["iv"]) - int(best["icv"]) - 2 < 60)
    conf = "Medium" if small >= 3 else "Low"
    return {"mode": "tunnel", "confidence": conf, "max_inner_min": mx,
            "reason": f"smallest inner packet is >= {max(0, mx - int(best.get('block') or 4) + 1)} B and "
                      f"<= {mx} B, consistent with an inner IP header on every packet"
                      + ("" if small >= 3 else "; few small packets seen, so transport cannot be excluded")}
