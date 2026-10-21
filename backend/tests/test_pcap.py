import struct

import pytest

from nunmathi.pcap import CaptureError, iter_frames, read_frame, read_packets


def _pcapng(frames):
    """Minimal little-endian pcapng writer: SHB, one Ethernet IDB, EPBs."""
    def block(btype, body):
        body += b"\0" * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 0))
    for ts, data in frames:
        us = int(round(ts * 1e6))
        out += block(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(data), len(data)) + data)
    return out


def test_rejects_non_capture(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"this is not a capture at all, just text" * 4)
    with pytest.raises(CaptureError):
        read_packets(str(p))


def test_pcap_counts_match_forge_truth(forged):
    path, truth, res = forged["branch-office"]
    pkts, stats = read_packets(path)
    assert stats["frames"] == len(pkts) + stats["other"]
    assert stats["ike"] > 0 and stats["esp"] > 0
    assert res["file"]["frames"] == stats["frames"]
    assert all(pkts[i].ts <= pkts[i + 1].ts for i in range(len(pkts) - 1))


def test_pcapng_reader_matches_pcap(forged, tmp_path):
    path, _, _ = forged["remote-access"]
    with open(path, "rb") as fh:
        frames = [(f.ts, f.data) for _, f in zip(range(300), iter_frames(fh))]
    ng = tmp_path / "same.pcapng"
    ng.write_bytes(_pcapng(frames))
    a, _ = read_packets(path, limit=300)
    b, _ = read_packets(str(ng))
    assert [(p.kind, p.src, p.dst, p.ip_len) for p in a] == [(p.kind, p.src, p.dst, p.ip_len) for p in b]
    assert abs(a[0].ts - b[0].ts) < 1e-5


def test_read_frame_random_access(forged):
    path, _, _ = forged["hardened-pq"]
    pkts, _ = read_packets(path, limit=50)
    fr = read_frame(path, pkts[10].idx)
    assert fr is not None and abs(fr.ts - pkts[10].ts) < 1e-9
    assert read_frame(path, 10**9) is None
