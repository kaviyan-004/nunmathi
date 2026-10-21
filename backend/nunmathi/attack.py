"""MITRE ATT&CK (Enterprise) mapping for Nunmathi findings.

Each rule is mapped to the adversary technique that the weakness enables or that the observation
indicates. The mapping is deliberately conservative: rules that describe hygiene or coverage
(DPD cadence, NAT-T, fragmentation, analysis bounds) are left unmapped rather than stretched.
"""
from __future__ import annotations

TACTICS = [
    ("TA0043", "Reconnaissance"), ("TA0001", "Initial Access"), ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"), ("TA0009", "Collection"), ("TA0005", "Defense Evasion"), ("TA0040", "Impact"),
]

TECHNIQUES = {
    "T1110.002": ("Brute Force: Password Cracking", "TA0006",
                  "Aggressive Mode PSK hashes can be captured passively and cracked offline."),
    "T1557": ("Adversary-in-the-Middle", "TA0006",
              "Weak or downgradable key exchange lets an on-path attacker break or steer the handshake."),
    "T1040": ("Network Sniffing", "TA0006",
              "Traffic that is weakly protected, or whose metadata identifies it, yields data to a passive sniffer."),
    "T1589.002": ("Gather Victim Identity Information: Email Addresses", "TA0043",
                  "IKE identities (FQDN / user@FQDN) disclosed in cleartext."),
    "T1592.002": ("Gather Victim Host Information: Software", "TA0043",
                  "Vendor ID payloads reveal the VPN product and often its version."),
    "T1499.002": ("Endpoint Denial of Service: Service Exhaustion Flood", "TA0040",
                  "Half-open IKE_SA_INIT floods exhaust responder state."),
    "T1600.001": ("Weaken Encryption: Reduce Key Space", "TA0005",
                  "Deprecated 64-bit block or short-key ciphers are what an attacker who weakens crypto aims for."),
    "T1046": ("Network Service Discovery", "TA0007",
              "Rejected key-exchange guesses reveal the responder's accepted groups."),
}

RULE_MAP = {
    "NM-100": ["T1557"],
    "NM-101": ["T1110.002", "T1557"],
    "NM-102": ["T1589.002"],
    "NM-110": ["T1040", "T1600.001"],
    "NM-111": ["T1557"],
    "NM-112": ["T1557"],
    "NM-113": ["T1557"],
    "NM-114": ["T1046"],
    "NM-120": ["T1040"],
    "NM-121": ["T1040", "T1600.001"],
    "NM-122": ["T1557"],
    "NM-130": ["T1040"],
    "NM-131": ["T1040"],
    "NM-150": ["T1040"],
    "NM-160": ["T1499.002"],
    "NM-170": ["T1592.002"],
}


def techniques_for(rule_id: str) -> list[dict]:
    return [{"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1],
             "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"}
            for t in RULE_MAP.get(rule_id, [])]


def matrix(alerts: list[dict]) -> dict:
    """Tactic columns with every mapped technique; hit techniques carry the alerts that triggered them."""
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    hits: dict[str, list[dict]] = {}
    for a in alerts:
        for t in RULE_MAP.get(a["id"], []):
            hits.setdefault(t, []).append({"id": a["id"], "uid": a.get("uid"), "risk": a["risk"],
                                           "tunnel": a.get("tunnel", "")})
    cols = []
    for tac, tname in TACTICS:
        techs = []
        for tid, (name, ta, why) in TECHNIQUES.items():
            if ta != tac:
                continue
            h = hits.get(tid, [])
            techs.append({"id": tid, "name": name, "why": why, "alerts": h,
                          "max_risk": min((x["risk"] for x in h), key=lambda r: order[r]) if h else None})
        if techs:
            cols.append({"id": tac, "name": tname, "techniques": techs})
    return {"version": "ATT&CK Enterprise v15 (subset relevant to IPsec)", "tactics": cols,
            "hit_techniques": sorted(hits), "unmapped_rules": sorted({a["id"] for a in alerts} - set(RULE_MAP))}
