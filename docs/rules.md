# Detection rules

Generated from `backend/nunmathi/assess.py` (also served at `GET /api/rules` and shown in the UI under *View → Rules*).

Score = 100 − 25·High − 10·Medium − 3·Low (floor 0). Letter: A+ ≥ 97, A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F. Any High caps the grade at C; three or more Highs force F.

| Rule | Name | Possible risk | Solution | References |
|---|---|---|---|---|
| NM-100 | **IKEv1 in use** — IKEv1 is deprecated (RFC 9395). It lacks IKEv2's anti-DoS cookies by default, has complex modes and several known protocol weaknesses. | Medium | Migrate to IKEv2 (strongSwan: version = 2 / libreswan: ikev2=insist). | RFC 9395 |
| NM-101 | **IKEv1 Aggressive Mode with pre-shared key** — The responder's HASH_R is sent before any encryption, which allows offline dictionary attacks on the PSK (ike-scan/psk-crack). | High, Medium | Disable Aggressive Mode; use IKEv2 with certificates or EAP. If PSK is unavoidable use >= 20 random characters. | CVE-2002-1623, RFC 2409 §5.4 |
| NM-102 | **Identity disclosed in cleartext** — The IKE identity is visible to any passive observer. | Medium | Use IKEv2 (identities are encrypted in IKE_AUTH) or Main Mode. | RFC 2409 |
| NM-110 | **Weak IKE encryption algorithm** — The IKE SA is protected by a 64-bit block or deprecated cipher. | High, Medium | Use AES-GCM-16 (256-bit) for IKE. | RFC 8221, RFC 8247 |
| NM-111 | **Weak or legacy IKE PRF/integrity** — MD5 is broken; SHA-1 is deprecated for new deployments. | High, Low | Use PRF HMAC-SHA2-384 or higher. | RFC 8247 |
| NM-112 | **Weak Diffie-Hellman group** — The key exchange provides less than 112 bits of classical security. | High, Medium | Use ECP-384, Curve25519 or MODP-3072+; add ML-KEM-768 (RFC 9370). | RFC 8247, NIST SP 800-57 |
| NM-113 | **Weak algorithms offered in proposal** — Weak transforms are still offered; a misconfigured peer or an active attacker could steer negotiation towards them. | Low | Remove 3DES, SHA-1, MD5 and MODP <= 1536 from the proposal list. | RFC 8247 |
| NM-114 | **Key-exchange group renegotiation (INVALID_KE_PAYLOAD)** — The initiator guessed a group the responder does not accept; adds a round trip and reveals the responder's preferred group. | Informational | Make the initiator's first KE guess match the responder's preferred group. | RFC 7296 §1.2 |
| NM-120 | **ESP-NULL: traffic is not encrypted** — Inner packets are visible on the wire; only integrity is provided. | High | Configure an encryption transform for ESP (e.g. aes256gcm16). | RFC 8221 §5 |
| NM-121 | **Weak ESP cipher (64-bit block)** — 64-bit block ciphers are vulnerable to birthday attacks (Sweet32) on long-lived SAs. | Medium | Use AES-GCM-16 or ChaCha20-Poly1305 for ESP. | CVE-2016-2183 (Sweet32) |
| NM-122 | **ESP integrity uses a truncated SHA-1/MD5 MAC** — Legacy integrity algorithm on ESP. | Low | Use AEAD (AES-GCM) or HMAC-SHA2-256-128 integrity. | RFC 8221 |
| NM-130 | **No Perfect Forward Secrecy on Child SA rekey** — Child SA keys are derived from the IKE SA key; compromise of the IKE SA exposes all Child SAs. | Medium | Add a DH group to esp_proposals (e.g. aes256gcm16-ecp384) so every rekey runs a fresh key exchange. | RFC 7296 §1.3.1 |
| NM-131 | **Long Child SA lifetime** — Long-lived keys increase the amount of data exposed per key. | Medium, Low | Set rekey_time <= 1 h for Child SAs (life_time ~ 1.1 x rekey_time). | NIST SP 800-77r1 |
| NM-132 | **Long IKE SA lifetime** — The IKE SA (and its authentication) is refreshed rarely. | Low | Set IKE rekey_time <= 8 h (strongSwan default 4 h). | NIST SP 800-77r1 |
| NM-150 | **Application traffic identifiable through encryption** — Packet sizes and timing reveal the application type despite encryption (traffic analysis). | Low, Informational | Enable TFC padding (strongSwan: tfc_padding = mtu) or a traffic-shaping overlay for sensitive flows. | RFC 4303 §2.7 (TFC) |
| NM-160 | **Half-open IKE flood observed** — Many IKE_SA_INIT requests without completion targeted the responder. | High, Medium | Enable IKEv2 cookies / rate limiting (strongSwan: charon.cookie_threshold, block_threshold). | RFC 8019 |
| NM-161 | **IKE fragmentation not negotiated** — Large IKE_AUTH messages (certificates, PQ keys) may be IP-fragmented and dropped by middleboxes. | Low, Informational | Enable IKEv2 fragmentation (RFC 7383): fragmentation = yes. | RFC 7383 |
| NM-162 | **NAT traversal in use** — ESP is UDP-encapsulated (port 4500), which indicates a NAT between the peers. IKE alone on port 4500 does not count. | Informational | None required; ensure UDP 4500 keepalives are within NAT timeouts. | RFC 3948 |
| NM-170 | **Implementation fingerprint via Vendor ID** — Vendor ID payloads reveal the IPsec implementation. | Low | Suppress vendor ID payloads (strongSwan: send_vendor_id = no). | RFC 7296 §3.12 |
| NM-171 | **Dead Peer Detection interval** — Observed liveness-check cadence. | Informational | Keep DPD enabled (30-120 s for remote access, <= 300 s for site-to-site). | RFC 3706, RFC 7296 §2.4 |
| NM-180 | **Analysis coverage note** — Aspects that could only be bounded from this capture. | Informational | Capture a longer period to measure the bounded values. |  |
