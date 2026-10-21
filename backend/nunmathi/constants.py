"""IANA registry values used by the IKE / ESP dissectors and the assessment rules.

Sources: IANA "Internet Key Exchange Version 2 (IKEv2) Parameters" and
"Internet Key Exchange (IKE) Attributes" registries, RFC 7296, RFC 9370.
"""

# ----------------------------------------------------------------- IKEv2
EXCHANGE_V2 = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    43: "IKE_INTERMEDIATE",
    44: "IKE_FOLLOWUP_KE",
}

PAYLOAD_V2 = {
    0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "Vendor ID", 44: "TSi",
    45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 53: "SKF",
}

PROTOCOL_ID = {1: "IKE", 2: "AH", 3: "ESP"}

TRANSFORM_TYPE = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "ESN",
                  6: "ADDKE1", 7: "ADDKE2", 8: "ADDKE3", 9: "ADDKE4",
                  10: "ADDKE5", 11: "ADDKE6", 12: "ADDKE7"}

ENCR = {
    1: "DES_IV64", 2: "DES", 3: "3DES", 5: "IDEA", 6: "CAST", 7: "BLOWFISH", 11: "NULL",
    12: "AES_CBC", 13: "AES_CTR", 14: "AES_CCM_8", 15: "AES_CCM_12", 16: "AES_CCM_16",
    18: "AES_GCM_8", 19: "AES_GCM_12", 20: "AES_GCM_16", 21: "NULL_AUTH_AES_GMAC",
    23: "CAMELLIA_CBC", 24: "CAMELLIA_CTR", 28: "CHACHA20_POLY1305",
}
AEAD_ENCR = {14, 15, 16, 18, 19, 20, 28}

PRF = {1: "HMAC_MD5", 2: "HMAC_SHA1", 3: "HMAC_TIGER", 4: "AES128_XCBC",
       5: "HMAC_SHA2_256", 6: "HMAC_SHA2_384", 7: "HMAC_SHA2_512", 8: "AES128_CMAC"}

INTEG = {0: "NONE", 1: "HMAC_MD5_96", 2: "HMAC_SHA1_96", 3: "DES_MAC", 4: "KPDK_MD5",
         5: "AES_XCBC_96", 6: "HMAC_MD5_128", 7: "HMAC_SHA1_160", 8: "AES_CMAC_96",
         12: "HMAC_SHA2_256_128", 13: "HMAC_SHA2_384_192", 14: "HMAC_SHA2_512_256"}
INTEG_ICV = {1: 12, 2: 12, 5: 12, 8: 12, 12: 16, 13: 24, 14: 32}

# Key exchange methods. 35-37 are ML-KEM (draft-ietf-ipsecme-ikev2-mlkem, IANA early allocation).
KE = {
    0: "NONE", 1: "MODP768", 2: "MODP1024", 5: "MODP1536", 14: "MODP2048", 15: "MODP3072",
    16: "MODP4096", 17: "MODP6144", 18: "MODP8192", 19: "ECP256", 20: "ECP384", 21: "ECP521",
    22: "MODP1024_S160", 23: "MODP2048_S224", 24: "MODP2048_S256", 25: "ECP192", 26: "ECP224",
    27: "BRAINPOOL224", 28: "BRAINPOOL256", 29: "BRAINPOOL384", 30: "BRAINPOOL512",
    31: "CURVE25519", 32: "CURVE448", 35: "ML_KEM_512", 36: "ML_KEM_768", 37: "ML_KEM_1024",
}
# public value size in bytes carried in the KE payload (initiator side for ML-KEM)
KE_SIZE = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024,
           19: 64, 20: 96, 21: 132, 22: 128, 23: 256, 24: 256, 25: 48, 26: 56,
           27: 56, 28: 64, 29: 96, 30: 128, 31: 32, 32: 56,
           35: 800, 36: 1184, 37: 1568}
# approximate classical security strength in bits (NIST SP 800-57 Pt 1)
KE_STRENGTH = {1: 60, 2: 80, 5: 90, 14: 112, 15: 128, 16: 152, 17: 176, 18: 200,
               19: 128, 20: 192, 21: 256, 22: 80, 23: 112, 24: 112, 25: 96, 26: 112,
               27: 112, 28: 128, 29: 192, 30: 256, 31: 128, 32: 224,
               35: 128, 36: 192, 37: 256}
PQ_KE = {35, 36, 37}

NOTIFY = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND",
    16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE", 16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED", 16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE", 16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED", 16393: "REKEY_SA", 16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO", 16396: "MOBIKE_SUPPORTED", 16404: "MULTIPLE_AUTH_SUPPORTED",
    16417: "EAP_ONLY_AUTHENTICATION", 16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS", 16435: "USE_PPK", 16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
}

# ----------------------------------------------------------------- IKEv1
EXCHANGE_V1 = {1: "Base", 2: "Main Mode", 3: "Authentication Only", 4: "Aggressive Mode",
               5: "Informational", 32: "Quick Mode", 33: "New Group Mode"}
PAYLOAD_V1 = {0: "NONE", 1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT",
              7: "CR", 8: "Hash", 9: "SIG", 10: "Nonce", 11: "Notification", 12: "Delete",
              13: "Vendor ID", 20: "NAT-D", 21: "NAT-OA", 130: "NAT-D (draft)"}
V1_ATTR = {1: "Encryption", 2: "Hash", 3: "Auth Method", 4: "Group", 11: "Life Type",
           12: "Life Duration", 14: "Key Length"}
V1_ENCR = {1: "DES", 2: "IDEA", 3: "BLOWFISH", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES_CBC"}
V1_HASH = {1: "MD5", 2: "SHA1", 3: "TIGER", 4: "SHA2_256", 5: "SHA2_384", 6: "SHA2_512"}
V1_AUTH = {1: "PSK", 2: "DSS", 3: "RSA_SIG", 4: "RSA_ENC", 5: "RSA_REV_ENC",
           64221: "HYBRID_RSA", 65001: "XAUTH_PSK", 65005: "XAUTH_RSA"}
# IKEv1 encryption id -> IKEv2 id, hash -> PRF id, so rules can share tables
V1_TO_V2_ENCR = {1: 2, 5: 3, 7: 12}
V1_TO_V2_PRF = {1: 1, 2: 2, 4: 5, 5: 6, 6: 7}

# ----------------------------------------------------------------- Vendor IDs
VENDOR_IDS = {
    "882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
    "4a131c81070358455c5728f20e95452f": "RFC 3947 NAT-T",
    "afcad71368a1f1c96b8696fc77570100": "Dead Peer Detection v1.0",
    "4048b7d56ebce88525e7de7f00d6c2d3": "IKE Fragmentation (IKEv1)",
    "90cb80913ebb696e086381b5ec427b1f": "draft-ietf-ipsec-nat-t-ike-02",
    "4f45766270707250445c6f766a": "Libreswan (prefix)",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco Unity",
    "1e2b516905991c7d7c96fcbfb587e461": "Microsoft Windows (MS NT5 ISAKMPOAKLEY)",
}

UDP_IKE = 500
UDP_NATT = 4500
IP_PROTO_ESP = 50
IP_PROTO_AH = 51
