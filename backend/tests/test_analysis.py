"""End-to-end checks against the forge's ground truth for every demo scenario."""
from nunmathi import assess, traffic


def ids(res):
    return {a["id"] for a in res["alerts"]}


def test_hardened_is_clean(forged):
    _, _, r = forged["hardened-pq"]
    t = r["tunnels"][0]
    assert t["version"] == 2
    assert t["ike_crypto"]["names"]["addke"], "ML-KEM additional key exchange should be decoded"
    assert t["pfs"]["status"] == "enabled"
    assert not {"qew", "quantum"} & set(t)
    assert r["grade"]["letter"] in ("A+", "A")


def test_legacy_ikev1_is_failed(forged):
    _, _, r = forged["legacy-ikev1"]
    assert {"NM-100", "NM-101", "NM-102", "NM-112"} <= ids(r)
    assert r["grade"]["letter"] == "F"


def test_misconfigured_lab_flags_esp_null_and_flood(forged):
    _, _, r = forged["misconfigured-lab"]
    assert {"NM-120", "NM-160"} <= ids(r)
    assert r["half_open"], "half-open IKE flood should be listed"
    assert any(c["geometry"]["esp_null"] for c in r["tunnels"][0]["child_sas"])


def test_remote_access_nat_and_invalid_ke(forged):
    _, _, r = forged["remote-access"]
    t = r["tunnels"][0]
    assert t["nat_t"]
    assert "NM-162" in ids(r)
    assert "NM-113" in ids(r)  # 3DES / MODP-1024 still offered


def test_esp_geometry_matches_truth(forged):
    for name, (_, truth, r) in forged.items():
        prof = truth["profile"] if "profile" in truth else truth
        if prof.get("esp_encr") is None:
            continue
        best = r["tunnels"][0]["child_sas"][0]["geometry"]["best"]
        if prof["esp_encr"] == 20:
            assert best["family"] == "AEAD", name
        elif prof["esp_encr"] == 12:
            assert best["family"] == "CBC" and best["block"] == 16, name


def test_grade_rules():
    mk = lambda *risks: [{"risk": x} for x in risks]  # noqa: E731
    assert assess.grade([])["letter"] == "A+"
    assert assess.grade(mk("High"))["letter"] in ("C", "D", "F")
    assert assess.grade(mk("High"))["score"] <= 75
    assert assess.grade(mk("High", "High", "High"))["letter"] == "F"


def test_what_if_recommended_improves_every_scenario(forged):
    order = ["F", "D", "C", "B", "A", "A+"]
    for name, (_, _, r) in forged.items():
        for t in r["tunnels"]:
            w = assess.what_if(t["posture"], t["recommended"], t["id"], t)
            before, after = w["before"]["grade"], w["after"]["grade"]
            assert after["score"] >= before["score"], name
            assert order.index(after["letter"]) >= order.index(before["letter"]), name
            assert set(w["resolved"]) <= set(w["before"]["alerts"])
            assert "connections" in w["config"]["strongswan"] and "conn " in w["config"]["libreswan"]


def test_traffic_model_generalises_to_fresh_synthetic_seed():
    m = traffic.get_model()
    X, y = traffic.synth_windows(60, seed=987654)
    pred = [d["label"] for d in m.predict(X)]
    truth = [traffic.CLASSES[int(k)] if not isinstance(k, str) else k for k in y]
    acc = sum(a == b for a, b in zip(pred, truth)) / len(truth)
    assert acc > 0.9, acc


def test_traffic_segments_cover_truth_classes(forged):
    _, truth, r = forged["branch-office"]
    seen = {s["label"] for s in r["tunnels"][0]["traffic"]["segments"]}
    want = {w["class"] for w in truth["class_windows"]}
    assert len(seen & want) >= max(1, len(want) - 1), (seen, want)
