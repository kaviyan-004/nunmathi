"""Built-in demo scenarios. Each is a tunnel profile understood by forge.generator."""
from __future__ import annotations

STRONGSWAN = "882fe56d6fd20dbc2251613b2ebe5beb"
NATT_V1 = "4a131c81070358455c5728f20e95452f"
DPD_V1 = "afcad71368a1f1c96b8696fc77570100"
CISCO_UNITY = "12f5f28c457168a9702d9fe274cc0100"
MS_NT5 = "1e2b516905991c7d7c96fcbfb587e46100000009"   # MD5 + 4-byte version

HARDENED = {
    "ike_version": 2, "ike_encr": 20, "ike_keylen": 256, "ike_prf": 6, "ike_integ": 0,
    "ike_group": 20, "addke": [36],
    "esp_encr": 20, "esp_keylen": 256, "esp_integ": 0, "pfs_group": 20,
    "ike_lifetime": 28800, "child_lifetime": 3600, "fragmentation": True, "auth": "cert",
}

SCENARIOS = {
    "hardened-pq": {
        **HARDENED,
        "title": "Hardened site-to-site (PQ hybrid)",
        "description": "IKEv2, AES-256-GCM, ECP-384 + ML-KEM-768 (RFC 9370), PFS, 1 h child lifetime.",
        "vendor_ids": [STRONGSWAN], "duration": 3 * 3600, "active_windows": 12, "seed": 11,
        "initiator": "198.51.100.23", "responder": "203.0.113.10",
    },
    "legacy-ikev1": {
        "title": "Legacy IKEv1 Aggressive Mode",
        "description": "IKEv1 Aggressive Mode with PSK, 3DES/SHA1/MODP-1024, ESP 3DES-SHA1, no PFS.",
        "ike_version": 1, "v1_mode": "aggressive", "v1_auth": 1, "v1_identity": "branch7@corp.example",
        "ike_encr": 3, "ike_prf": 2, "ike_integ": 2, "ike_group": 2,
        "esp_encr": 3, "esp_integ": 2, "pfs_group": None,
        "ike_lifetime": 86400, "child_lifetime": 28800, "vendor_ids": [CISCO_UNITY, DPD_V1, NATT_V1],
        "duration": 2 * 3600, "active_windows": 10, "seed": 22, "dpd": 120,
        "initiator": "192.0.2.77", "responder": "203.0.113.200",
    },
    "remote-access": {
        "title": "Remote-access road warrior (NAT-T)",
        "description": "IKEv2 AES-CBC-128 / SHA-256 / MODP-2048 behind NAT, no PFS; initiator also offers 3DES and MODP-1024.",
        "ike_version": 2, "ike_encr": 12, "ike_keylen": 128, "ike_prf": 5, "ike_integ": 12, "ike_group": 14,
        "offer_extra": [{"ike_encr": 3, "ike_keylen": None, "ike_group": 2}],
        "initiator_guess_group": 19,
        "esp_encr": 12, "esp_keylen": 128, "esp_integ": 12, "pfs_group": None,
        "ike_lifetime": 14400, "child_lifetime": 3600, "natt": True, "fragmentation": True, "auth": "cert",
        "remote_access": True, "vendor_ids": [MS_NT5], "responder_vendor_ids": [STRONGSWAN],
        "duration": int(2.5 * 3600), "active_windows": 12, "seed": 33, "dpd": 60,
        "initiator": "100.64.12.9", "responder": "203.0.113.10",
    },
    "branch-office": {
        "title": "Branch office, long lifetimes",
        "description": "IKEv2 AES-128-GCM / X25519 with PFS, but 12 h child and 24 h IKE lifetimes.",
        "ike_version": 2, "ike_encr": 20, "ike_keylen": 128, "ike_prf": 5, "ike_integ": 0, "ike_group": 31,
        "esp_encr": 20, "esp_keylen": 128, "esp_integ": 0, "pfs_group": 31,
        "ike_lifetime": 86400, "child_lifetime": 43200, "fragmentation": False, "auth": "psk",
        "vendor_ids": [STRONGSWAN], "duration": 26 * 3600, "active_windows": 14, "seed": 44, "dpd": 900,
        "initiator": "198.51.100.150", "responder": "203.0.113.44",
    },
    "misconfigured-lab": {
        "title": "Misconfigured lab gateway (ESP-NULL, flood)",
        "description": "IKEv2 AES-CBC-256 / SHA-1 / MODP-1536, ESP-NULL (integrity only), no PFS, half-open IKE flood.",
        "ike_version": 2, "ike_encr": 12, "ike_keylen": 256, "ike_prf": 2, "ike_integ": 2, "ike_group": 5,
        "esp_encr": 11, "esp_integ": 2, "pfs_group": None,
        "ike_lifetime": 10800, "child_lifetime": 1800, "fragmentation": False, "auth": "psk",
        "duration": 5400, "active_windows": 10, "seed": 55, "half_open_flood": 160, "flood_at": 2000,
        "initiator": "10.20.0.5", "responder": "10.20.0.1",
    },
}
