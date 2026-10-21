"""Live mode: replay, a fake capture tool, tool failures, the REST/SSE API and (if usable) real dumpcap on lo."""
import os
import socket
import stat
import time

import pytest
from fastapi.testclient import TestClient

from nunmathi import live
from nunmathi.analyzer import analyze_file
from nunmathi.api import app

DATA = os.path.join(os.path.dirname(__file__), "data")
CBC = os.path.join(DATA, "strongswan-cbc.pcap")


@pytest.fixture(scope="module")
def client(data_dir):
    return TestClient(app)


def _wait(s, timeout=60):
    end = time.time() + timeout
    while s.running and time.time() < end:
        time.sleep(0.2)
    s.join(10)
    assert not s.running, "live session did not finish"


def _fake_tool(tmp_path, body: str) -> dict:
    p = tmp_path / "fakecap"
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return {"name": "dumpcap", "path": str(p), "privileged": True, "note": "test"}


def test_replay_matches_offline_analysis(data_dir):
    s = live.start(replay=CBC, speed=50, interval=0.5)
    _wait(s)
    assert s.state == "done" and s.stop_reason == "replay finished"
    from nunmathi import store
    res, off = store.load_result(s.aid), analyze_file(CBC)
    assert res["file"]["frames"] == off["file"]["frames"]
    assert res["grade"] == off["grade"]
    assert [a["id"] for a in res["alerts"]] == [a["id"] for a in off["alerts"]]
    assert all("first_seen" in a for a in res["alerts"])
    kinds = {e["type"] for e in res["live"]["events"]}
    assert {"capture", "tunnel", "alert", "rekey"} <= kinds
    meta = store.get(s.aid)
    assert meta["status"] == "done" and meta["source"] == "live" and meta["grade"] == off["grade"]["letter"]
    assert os.path.getsize(store.capture_path(s.aid)) == meta["size"] > 0


def test_capture_tool_stream(monkeypatch, tmp_path, data_dir):
    """Interface mode end to end, with a stand-in capture tool that writes pcap to stdout slowly."""
    tool = _fake_tool(tmp_path, f'head -c 60000 "{CBC}"; sleep 1; tail -c +60001 "{CBC}"')
    monkeypatch.setattr(live, "backends", lambda: [tool])
    s = live.start(interface="eth0", interval=0.3)
    assert s.cmd[:3] == [tool["path"], "-i", "eth0"] and s.cmd[-1] == live.DEFAULT_FILTER
    _wait(s)
    assert s.state == "done" and "exited" in s.stop_reason
    assert s.stats["frames"] == analyze_file(CBC)["file"]["frames"]
    assert s.analyses >= 2          # analyzed while the stream was still arriving, then once more at the end


def test_capture_tool_failure_is_reported(monkeypatch, tmp_path, data_dir):
    tool = _fake_tool(tmp_path, 'echo "vA: You don\'t have permission to capture on that device" >&2; exit 1')
    monkeypatch.setattr(live, "backends", lambda: [tool])
    s = live.start(interface="vA")
    _wait(s)
    assert s.state == "failed" and "permission" in s.error and "cap_net_raw" in s.error
    from nunmathi import store
    assert store.get(s.aid)["status"] == "failed"


def test_stop_and_limits(monkeypatch, tmp_path, data_dir):
    tool = _fake_tool(tmp_path, f'cat "{CBC}"; sleep 30')
    monkeypatch.setattr(live, "backends", lambda: [tool])
    s = live.start(interface="eth0", max_packets=100)
    _wait(s)
    assert "packet limit" in s.stop_reason and s.state == "done"
    s = live.start(interface="eth0", duration=1)
    _wait(s)
    assert "duration" in s.stop_reason


def test_api_validation(client):
    assert client.get("/api/live/capabilities").json()["default_filter"] == live.DEFAULT_FILTER
    assert client.post("/api/live", json={"interface": "eth0; rm -rf /"}).status_code == 400
    assert client.post("/api/live", json={}).status_code == 400
    assert client.post("/api/live", json={"replay_scenario": "nope"}).status_code == 404
    assert client.get("/api/live/doesnotexist").status_code == 404


def test_api_replay_stream_and_stop(client):
    r = client.post("/api/live", json={"replay_scenario": "branch-office", "speed": 100, "interval": 0.5})
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    assert r.json()["running"] and r.json()["source"] == "replay"
    assert aid in [x["id"] for x in client.get("/api/live").json()]
    for _ in range(100):
        if client.get(f"/api/live/{aid}").json()["stats"]["frames"] > 20:
            break
        time.sleep(0.1)
    assert client.post(f"/api/live/{aid}/stop").status_code == 200
    for _ in range(100):
        if client.get(f"/api/analyses/{aid}").json()["status"] in ("done", "failed"):
            break
        time.sleep(0.2)
    meta = client.get(f"/api/analyses/{aid}").json()
    assert meta["status"] == "done", meta
    ev = client.get(f"/api/live/{aid}").json()["events"]
    assert any("stopped by user" in e["text"] for e in ev)
    # TestClient buffers whole responses, so read the SSE stream once it is finite (capture ended)
    body = client.get(f"/api/live/{aid}/stream").text
    assert body.startswith("event: status\ndata: {") and body.rstrip().endswith("event: end\ndata: {}")
    page = client.get(f"/api/analyses/{aid}/packets?kind=IKE&limit=3").json()
    assert page["total"] > 0
    assert client.get(f"/api/analyses/{aid}/packets/{page['items'][0]['idx']}").json()["ike"]


def _dumpcap_usable():
    b = next((x for x in live.backends() if x["name"] == "dumpcap"), None)
    return bool(b and b["privileged"] and os.access(b["path"], os.X_OK))


@pytest.mark.skipif(not _dumpcap_usable(), reason="dumpcap without capture privileges")
def test_real_dumpcap_on_loopback(data_dir):
    """Real capture from the kernel: IKE-shaped UDP/500 datagrams sent over lo are seen live."""
    s = live.start(interface="lo", bpf="udp port 500", interval=0.5)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(100):                    # wait for dumpcap to open the device
        if s.state == "capturing" or not s.running:
            break
        sock.sendto(b"\x00" * 28, ("127.0.0.1", 500))
        time.sleep(0.1)
    for _ in range(5):
        sock.sendto(bytes(range(40)), ("127.0.0.1", 500))
    time.sleep(1.5)
    s.stop()
    _wait(s)
    assert s.error is None, s.error
    assert s.stats["frames"] >= 5 and s.stats["ike"] >= 5
