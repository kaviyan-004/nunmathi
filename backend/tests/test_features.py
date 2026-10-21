"""Testbed, apply-recommendation verification, SHAP, PDF reports and the versioned JSON schema."""
import io
import time

import jsonschema
import pytest
from fastapi.testclient import TestClient

from nunmathi import pdfreports, report, schema, testbed, verify
from nunmathi.api import app

SPEC = """
testbed: 1
name: unit
duration: 10m
seed: 3
tunnels:
  - name: weak
    initiator: 192.0.2.10
    responder: 203.0.113.1
    ike:
      version: 1
      proposal: 3des-sha1-modp1024
      lifetime: 1h
    esp:
      proposal: 3des-sha1
      lifetime: 20m
    traffic: {classes: [web, voip], windows: 6}
"""


@pytest.fixture(scope="module")
def client(data_dir):
    return TestClient(app)


@pytest.fixture(scope="module")
def tb(client):
    r = client.post("/api/testbed/run?sync=true", json={"spec": SPEC})
    assert r.status_code == 201, r.text
    a = client.get(f"/api/analyses/{r.json()['id']}").json()
    assert a["status"] == "done", a
    return a


def _pages(pdf: bytes) -> int:
    from pypdf import PdfReader
    return len(PdfReader(io.BytesIO(pdf)).pages)


def test_example_spec_is_valid():
    v = testbed.load(testbed.EXAMPLE)
    assert len(v["tunnels"]) == 3 and {t["name"] for t in testbed.summary(v)} >= {"road-warrior"}


@pytest.mark.parametrize("bad, msg", [("tunnels: []", "at least one"), ("foo: 1\ntunnels: [x]", "unknown top-level"),
                                      ("- a", "mapping")])
def test_spec_errors(bad, msg):
    with pytest.raises(testbed.SpecError, match=msg):
        testbed.load(bad)


def test_testbed_api(client, tb):
    assert client.get("/api/testbed/example").json()["spec"].startswith("#")
    ok = client.post("/api/testbed/validate", json={"spec": SPEC}).json()
    assert ok["valid"] and ok["tunnels"][0]["name"] == "weak"
    assert not client.post("/api/testbed/validate", json={"spec": "tunnels: 3"}).json()["valid"]
    assert client.post("/api/testbed/run", json={"spec": "nope: 1"}).status_code == 400
    assert tb["source"] == "testbed" and tb["grade"] == "F"
    assert "3des" in client.get(f"/api/analyses/{tb['id']}/testbed.yaml").text


def test_result_strips_features_and_explain(client, tb):
    res = client.get(f"/api/analyses/{tb['id']}/result").json()
    t = res["tunnels"][0]
    assert "x" not in t["traffic"]["windows"][0]
    g = client.get(f"/api/analyses/{tb['id']}/tunnels/{t['id']}/explain").json()
    assert g["windows"] > 0 and g["features"][0]["mean_abs_phi"] >= g["features"][-1]["mean_abs_phi"]
    w = client.get(f"/api/analyses/{tb['id']}/tunnels/{t['id']}/explain?window=0").json()
    # efficiency: the attributions add up to f(x) - E[f]
    assert abs(w["sum_phi"] - (w["prediction"] - w["base_value"])) < 0.02
    assert client.get(f"/api/analyses/{tb['id']}/tunnels/{t['id']}/explain?window=99999").status_code == 404


def test_apply_recommendation_verified(client, tb):
    res = client.get(f"/api/analyses/{tb['id']}/result").json()
    t = res["tunnels"][0]
    r = client.post(f"/api/analyses/{tb['id']}/whatif/verify", json={"tunnel": t["id"], "changes": t["recommended"]})
    assert r.status_code == 202
    jid = r.json()["id"]
    for _ in range(300):
        job = client.get(f"/api/verify/{jid}").json()
        if job["status"] != "running":
            break
        time.sleep(0.2)
    assert job["status"] == "done", job
    v = job["result"]
    assert v["hardened"]["measured"]["grade"]["score"] > v["baseline"]["measured"]["grade"]["score"]
    assert all(c["verified"] for c in v["checks"]), v["checks"]
    assert "NM-100" in v["resolved"] and v["prediction_agrees"]
    assert client.post(f"/api/analyses/{tb['id']}/whatif/verify",
                       json={"tunnel": t["id"], "changes": ["bogus"]}).status_code == 400


def test_pdf_reports(client, tb):
    ex = client.get(f"/api/analyses/{tb['id']}/report/executive.pdf")
    assert ex.status_code == 200 and ex.content[:5] == b"%PDF-" and 2 <= _pages(ex.content) <= 3
    te = client.get(f"/api/analyses/{tb['id']}/report/technical.pdf")
    assert te.status_code == 200 and 15 <= _pages(te.content) <= 30
    assert client.get(f"/api/analyses/{tb['id']}/report/other.pdf").status_code == 404


def test_json_export_matches_schema(client, tb):
    sc = client.get("/api/schema/report.json").json()
    jsonschema.Draft202012Validator.check_schema(sc)
    doc = client.get(f"/api/analyses/{tb['id']}/report.json").json()
    errs = list(jsonschema.Draft202012Validator(sc).iter_errors(doc))
    assert not errs, [e.message for e in errs[:3]]
    assert doc["schema_version"] == schema.SCHEMA_VERSION and doc["audit"]
    assert any(t["techniques"] for t in doc["attack"]["tactics"])


def test_rules_carry_standards_and_attack(client):
    rules = {r["id"]: r for r in client.get("/api/rules").json()}
    assert rules["NM-100"]["standards"] and isinstance(rules["NM-100"]["attack"], list)
