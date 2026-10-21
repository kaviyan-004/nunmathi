"""Regression tests on captures of real strongSwan 6.0.7 tunnels (rootless network namespaces).

The fixtures keep every IKE packet and the first 40 ESP packets of each SPI, so crypto, rekeys,
lifetimes, PFS and geometry are real; traffic classes are not checked because ESP was subsampled.
Side A: lifetime=40s margintime=10s (Child SA rekey every 30 s), ikelifetime=95s with reauth=yes
(a fresh IKE_SA_INIT every 85 s). IKE floats to UDP 4500 although there is no NAT.
"""
import os

import pytest

from nunmathi.analyzer import analyze_file
from nunmathi.geometry import solve

DATA = os.path.join(os.path.dirname(__file__), "data")


@pytest.fixture(scope="module")
def real():
    return {n: analyze_file(os.path.join(DATA, f"strongswan-{n}.pcap")) for n in ("pq", "cbc")}


def _ids(r):
    return {a["id"] for a in r["alerts"]}


def test_pq_hybrid_tunnel(real):
    r = real["pq"]
    t = r["tunnels"][0]
    names = t["ike_crypto"]["names"]
    assert (names["encr"], names["prf"], names["group"]) == ("AES_GCM_16_256", "HMAC_SHA2_384", "ECP384")
    assert names["addke"] == ["ML_KEM_768"]
    assert t["pfs"]["status"] == "enabled" and t["pfs"]["group_id"] == 20
    assert r["grade"]["letter"] in ("A+", "A")


def test_cbc_tunnel_without_pfs(real):
    t = real["cbc"]["tunnels"][0]
    names = t["ike_crypto"]["names"]
    assert (names["encr"], names["group"]) == ("AES_CBC_128", "MODP2048")
    assert t["pfs"]["status"] == "disabled"
    assert "NM-130" in _ids(real["cbc"])


@pytest.mark.parametrize("name", ["pq", "cbc"])
def test_lifetimes_include_ikev2_reauth(real, name):
    lt = real[name]["tunnels"][0]["lifetimes"]
    assert lt["child_rekey_interval"] == 30
    assert lt["ike_rekey_interval"] == 85          # reauth=yes: new IKE_SA_INIT at ikelifetime - margintime
    assert any(s["origin"] == "reauth" for s in real[name]["tunnels"][0]["ike_sas"])


@pytest.mark.parametrize("name", ["pq", "cbc"])
def test_ike_on_4500_is_not_nat_traversal(real, name):
    t = real[name]["tunnels"][0]
    assert t["ike_port_4500"] and not t["nat_t"]
    assert "NM-162" not in _ids(real[name])


def test_esp_geometry_not_overclaimed(real):
    # a voip-only Child SA has one ESP length that fits several block sizes; it must not be called 3DES
    assert "NM-121" not in _ids(real["pq"])
    assert real["pq"]["tunnels"][0]["posture"]["esp_family"] == "AEAD"
    assert real["cbc"]["tunnels"][0]["posture"]["esp_key"] == "cbc128-icv96"


def test_geometry_single_length_is_ambiguous():
    g = solve([220] * 400)
    assert g["best"]["family"] == "AMBIGUOUS" and g["confidence"] == "Low"
    assert len(g["best"]["alternatives"]) >= 2


def test_geometry_many_lengths_resolves_cbc64():
    lengths = [8 + 8 + 12 + 8 * k for k in range(4, 60)] * 3
    g = solve(lengths)
    assert g["best"]["family"] == "CBC64" and g["confidence"] == "High"
