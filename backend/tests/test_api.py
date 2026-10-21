import pytest
from fastapi.testclient import TestClient

from nunmathi.api import app


@pytest.fixture(scope="module")
def client(data_dir):
    return TestClient(app)


@pytest.fixture(scope="module")
def demo(client):
    r = client.post("/api/analyses/demo/branch-office?sync=true")
    assert r.status_code == 201
    a = client.get(f"/api/analyses/{r.json()['id']}").json()
    assert a["status"] == "done", a
    return a


def test_health_and_catalogues(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert len(client.get("/api/scenarios").json()) == 5
    rules = client.get("/api/rules").json()
    assert {"id", "name", "description", "solution", "references"} <= set(rules[0])
    assert {c["id"] for c in client.get("/api/changes").json()} >= {"ikev2", "pq_hybrid", "pfs"}
    assert client.get("/api/model-card").json()["test_accuracy"] > 0.9


def test_result_packets_and_frame(client, demo):
    aid = demo["id"]
    res = client.get(f"/api/analyses/{aid}/result").json()
    assert res["tunnels"] and res["grade"]["letter"] == demo["grade"]
    page = client.get(f"/api/analyses/{aid}/packets?kind=IKE&limit=5").json()
    assert page["total"] > 0 and len(page["items"]) == 5
    assert page["items"][0]["info"].startswith("IKEv2 IKE_SA_INIT request")
    fr = client.get(f"/api/analyses/{aid}/packets/{page['items'][0]['idx']}").json()
    assert [layer["name"] for layer in fr["layers"]][-1] == "IKE"
    assert fr["ike"]["exchange_name"] == "IKE_SA_INIT"
    assert client.get(f"/api/analyses/{aid}/packets/99999999").status_code == 404


def test_whatif(client, demo):
    aid = demo["id"]
    t = client.get(f"/api/analyses/{aid}/result").json()["tunnels"][0]
    r = client.post(f"/api/analyses/{aid}/whatif", json={"tunnel": t["id"], "changes": t["recommended"]})
    assert r.status_code == 200 and r.json()["after"]["grade"]["score"] >= r.json()["before"]["grade"]["score"]
    assert client.post(f"/api/analyses/{aid}/whatif", json={"tunnel": t["id"], "changes": ["bogus"]}).status_code == 400
    assert client.post(f"/api/analyses/{aid}/whatif", json={"tunnel": "T99", "changes": []}).status_code == 404


@pytest.mark.parametrize("fmt,ctype,magic", [("html", "text/html", b"<!doctype html>"),
                                             ("json", "application/json", b"{"),
                                             ("pdf", "application/pdf", b"%PDF")])
def test_reports(client, demo, fmt, ctype, magic):
    r = client.get(f"/api/analyses/{demo['id']}/report.{fmt}")
    assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)
    assert r.content.startswith(magic)


def test_upload_sanitises_name_and_rejects_garbage(client, forged):
    path, _, _ = forged["legacy-ikev1"]
    with open(path, "rb") as fh:
        body = fh.read()
    r = client.post("/api/analyses?filename=../../etc/my%20cap.pcap&sync=true", content=body)
    assert r.status_code == 201
    a = client.get(f"/api/analyses/{r.json()['id']}").json()
    assert a["name"] == "my_cap.pcap" and a["status"] == "done" and a["grade"] == "F"

    r = client.post("/api/analyses?filename=x.pcap&sync=true", content=b"garbage" * 10)
    a = client.get(f"/api/analyses/{r.json()['id']}").json()
    assert a["status"] == "failed" and "pcap" in a["error"].lower()
    assert client.post("/api/analyses?filename=x.pcap", content=b"tiny").status_code == 400


def test_delete(client):
    r = client.post("/api/analyses/demo/hardened-pq?sync=true").json()
    assert client.delete(f"/api/analyses/{r['id']}").status_code == 200
    assert client.get(f"/api/analyses/{r['id']}").status_code == 404
    assert client.get("/api/analyses/doesnotexist/result").status_code == 404
