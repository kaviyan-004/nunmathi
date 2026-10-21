import random

from nunmathi import ike
from nunmathi.geometry import solve
from nunmathi.pcap import read_packets


def _ike_msgs(path, n=40):
    pkts, _ = read_packets(path, limit=4000)
    return [ike.parse(p.payload) for p in pkts if p.kind == "IKE"][:n]


def test_ikev2_sa_init_decoded(forged):
    path, _, _ = forged["hardened-pq"]
    m = _ike_msgs(path)[0]
    assert m.version == 2 and m.exchange_name == "IKE_SA_INIT" and not m.response
    d = m.to_dict()
    names = {t["name"] for p in d["proposals"] for t in p["transforms"]}
    assert any("ML_KEM_768" in n for n in names), names
    assert d["ke_group"] == 20


def test_ikev1_aggressive_identity_in_clear(forged):
    path, _, _ = forged["legacy-ikev1"]
    m = _ike_msgs(path)[0]
    assert m.version == 1
    assert "Aggressive" in m.exchange_name
    assert any("branch7@corp.example" in str(i) for i in m.to_dict()["identities"])


def test_truncated_ike_raises():
    try:
        ike.parse(b"\x01\x02\x03")
    except ike.IKEParseError:
        return
    raise AssertionError("expected IKEParseError")


def _gcm(p):
    return 8 + 8 + (p + 2 + 3) // 4 * 4 + 16


def _cbc(p):
    return 8 + 16 + (p + 2 + 15) // 16 * 16 + 16


def test_geometry_aead_vs_cbc():
    r = random.Random(7)
    a = solve([_gcm(r.randint(40, 1400)) for _ in range(300)])
    b = solve([_cbc(r.randint(40, 1400)) for _ in range(300)])
    assert a["best"]["family"] == "AEAD" and a["confidence"] == "High"
    assert b["best"]["family"] == "CBC" and b["best"]["block"] == 16 and b["best"]["icv"] == 16


def test_geometry_empty():
    assert solve([])["best"] is None
