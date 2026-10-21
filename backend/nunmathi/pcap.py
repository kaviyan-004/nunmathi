"""Minimal, dependency-free pcap / pcapng reader and IPsec-aware L2-L4 decoder.

Only headers are read. ESP payloads stay opaque: Nunmathi never decrypts.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator

from .constants import IP_PROTO_AH, IP_PROTO_ESP, UDP_IKE, UDP_NATT

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

LINK_NULL, LINK_ETHERNET, LINK_RAW, LINK_RAW4, LINK_RAW6, LINK_SLL, LINK_SLL2 = 0, 1, 101, 228, 229, 113, 276


class CaptureError(ValueError):
    """Raised for files that are not a readable pcap / pcapng capture."""


@dataclass
class Frame:
    ts: float
    linktype: int
    data: bytes


@dataclass
class Packet:
    idx: int                 # 1-based frame number, like Wireshark
    ts: float
    src: str
    dst: str
    ip_version: int
    ip_len: int              # IP total length (bytes on the wire above L2)
    l4: str                  # "UDP", "ESP", "AH", other
    sport: int = 0
    dport: int = 0
    kind: str = "OTHER"      # IKE | ESP | NAT-KA | AH | OTHER
    payload: bytes = b""     # IKE message or ESP packet (SPI .. ICV)
    layers: list = field(default_factory=list)   # [(name, offset, length)] for the hex view
    plen: int = -1           # true payload length when `payload` was trimmed (live capture keeps only a prefix)

    @property
    def size(self) -> int:
        return self.plen if self.plen >= 0 else len(self.payload)

    def trim(self, keep: int = 64) -> "Packet":
        """Drop ESP/AH ciphertext beyond `keep` bytes; only lengths and the header prefix are ever used."""
        if self.kind in ("ESP", "AH") and len(self.payload) > keep:
            self.plen, self.payload = len(self.payload), self.payload[:keep]
        return self


# ------------------------------------------------------------------ readers
def iter_frames(fh: BinaryIO) -> Iterator[Frame]:
    head = fh.read(4)
    if head in PCAP_MAGICS:
        yield from _iter_pcap(fh, head)
    elif head == PCAPNG_SHB:
        yield from _iter_pcapng(fh, head)
    else:
        raise CaptureError("Not a pcap or pcapng file (unknown magic number).")


def _iter_pcap(fh: BinaryIO, magic: bytes) -> Iterator[Frame]:
    endian, tsres = PCAP_MAGICS[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        raise CaptureError("Truncated pcap global header.")
    linktype = struct.unpack(endian + "HHiIII", rest)[5] & 0x0FFFFFFF
    while True:
        rh = fh.read(16)
        if len(rh) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rh)
        if incl > 262144:
            raise CaptureError("Corrupt pcap record length.")
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield Frame(sec + frac * tsres, linktype, data)


def _iter_pcapng(fh: BinaryIO, first: bytes) -> Iterator[Frame]:
    endian = "<"
    ifaces: list[tuple[int, float]] = []
    btype_raw = first
    while True:
        if btype_raw is None:
            btype_raw = fh.read(4)
        if len(btype_raw) < 4:
            return
        lraw = fh.read(4)
        if len(lraw) < 4:
            return
        if btype_raw == PCAPNG_SHB:
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", lraw)[0]
            body = bom + fh.read(blen - 16)
            ifaces = []
        else:
            blen = struct.unpack(endian + "I", lraw)[0]
            if blen < 12 or blen > 16 * 1024 * 1024:
                raise CaptureError("Corrupt pcapng block length.")
            body = fh.read(blen - 12)
        fh.read(4)  # trailing length
        btype = struct.unpack(endian + "I", btype_raw)[0]
        btype_raw = None
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            tsres = 1e-6
            opts = body[8:]
            while len(opts) >= 4:
                code, olen = struct.unpack(endian + "HH", opts[:4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = opts[4]
                    tsres = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opts = opts[4 + ((olen + 3) & ~3):]
            ifaces.append((linktype, tsres))
        elif btype == 6:  # Enhanced Packet Block
            iface, tsh, tsl, incl, _orig = struct.unpack(endian + "IIIII", body[:20])
            lt, res = ifaces[iface] if iface < len(ifaces) else (LINK_ETHERNET, 1e-6)
            yield Frame(((tsh << 32) | tsl) * res, lt, body[20:20 + incl])
        elif btype == 3:  # Simple Packet Block
            lt, _ = ifaces[0] if ifaces else (LINK_ETHERNET, 1e-6)
            yield Frame(0.0, lt, body[4:])


# ------------------------------------------------------------------ decoder
def _l3_offset(fr: Frame) -> tuple[int, int] | None:
    """Return (offset of IP header, ethertype-ish version hint) or None."""
    d, lt = fr.data, fr.linktype
    if lt == LINK_ETHERNET:
        off, etype = 14, struct.unpack("!H", d[12:14])[0] if len(d) >= 14 else 0
        while etype in (0x8100, 0x88A8) and len(d) >= off + 4:   # VLAN tags
            etype = struct.unpack("!H", d[off + 2:off + 4])[0]
            off += 4
        return (off, etype) if etype in (0x0800, 0x86DD) else None
    if lt in (LINK_RAW, LINK_RAW4, LINK_RAW6):
        return (0, 0)
    if lt == LINK_SLL:
        return (16, struct.unpack("!H", d[14:16])[0])
    if lt == LINK_SLL2:
        return (20, struct.unpack("!H", d[0:2])[0])
    if lt == LINK_NULL:
        return (4, 0)
    return None


def decode(fr: Frame, idx: int) -> Packet | None:
    loc = _l3_offset(fr)
    if loc is None:
        return None
    off = loc[0]
    d = fr.data
    if len(d) < off + 20:
        return None
    ver = d[off] >> 4
    layers = []
    if off:
        layers.append(("Link", 0, off))
    if ver == 4:
        ihl = (d[off] & 0x0F) * 4
        ip_len = struct.unpack("!H", d[off + 2:off + 4])[0]
        frag = struct.unpack("!H", d[off + 6:off + 8])[0]
        proto = d[off + 9]
        src = str(ipaddress.IPv4Address(d[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(d[off + 16:off + 20]))
        if frag & 0x1FFF:  # non-first fragment: no L4 header
            return Packet(idx, fr.ts, src, dst, 4, ip_len, "IP-FRAG", layers=layers)
        l4off = off + ihl
        layers.append(("IPv4", off, ihl))
    elif ver == 6:
        if len(d) < off + 40:
            return None
        ip_len = struct.unpack("!H", d[off + 4:off + 6])[0] + 40
        proto = d[off + 6]
        src = str(ipaddress.IPv6Address(d[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(d[off + 24:off + 40]))
        l4off = off + 40
        while proto in (0, 43, 60) and len(d) >= l4off + 8:   # hop-by-hop, routing, dest opts
            proto, hlen = d[l4off], (d[l4off + 1] + 1) * 8
            l4off += hlen
        layers.append(("IPv6", off, l4off - off))
    else:
        return None
    end = min(len(d), off + ip_len)

    if proto == IP_PROTO_ESP:
        layers.append(("ESP", l4off, end - l4off))
        return Packet(idx, fr.ts, src, dst, ver, ip_len, "ESP", kind="ESP", payload=d[l4off:end], layers=layers)
    if proto == IP_PROTO_AH:
        layers.append(("AH", l4off, end - l4off))
        return Packet(idx, fr.ts, src, dst, ver, ip_len, "AH", kind="AH", payload=d[l4off:end], layers=layers)
    if proto != 17 or len(d) < l4off + 8:
        return Packet(idx, fr.ts, src, dst, ver, ip_len, f"IP/{proto}", layers=layers)

    sport, dport = struct.unpack("!HH", d[l4off:l4off + 4])
    layers.append(("UDP", l4off, 8))
    body = d[l4off + 8:end]
    boff = l4off + 8
    pkt = Packet(idx, fr.ts, src, dst, ver, ip_len, "UDP", sport, dport, layers=layers)
    ports = {sport, dport}
    if UDP_NATT in ports:
        if body == b"\xff":
            pkt.kind = "NAT-KA"
            layers.append(("NAT-Keepalive", boff, 1))
        elif body[:4] == b"\x00\x00\x00\x00":
            pkt.kind, pkt.payload = "IKE", body[4:]
            layers.append(("Non-ESP marker", boff, 4))
            layers.append(("IKE", boff + 4, len(body) - 4))
        elif len(body) >= 8:
            pkt.kind, pkt.payload = "ESP", body
            layers.append(("ESP (UDP-encap)", boff, len(body)))
    elif UDP_IKE in ports and len(body) >= 28:
        pkt.kind, pkt.payload = "IKE", body
        layers.append(("IKE", boff, len(body)))
    return pkt


_STAT_KEY = {"IKE": "ike", "ESP": "esp", "NAT-KA": "nat_keepalive", "AH": "ah"}


def new_stats() -> dict:
    return {"frames": 0, "ike": 0, "esp": 0, "nat_keepalive": 0, "ah": 0, "other": 0,
            "first_ts": None, "last_ts": None, "bytes": 0}


def account(stats: dict, fr: Frame, idx: int) -> Packet | None:
    """Count one frame into `stats`; return its decoded packet when it is IPsec-relevant."""
    stats["frames"] += 1
    stats["bytes"] += len(fr.data)
    if stats["first_ts"] is None:
        stats["first_ts"] = fr.ts
    stats["last_ts"] = fr.ts
    p = decode(fr, idx)
    if p is None or p.kind not in _STAT_KEY:
        stats["other"] += 1
        return None
    stats[_STAT_KEY[p.kind]] += 1
    return p


def read_packets(path: str, limit: int | None = None) -> tuple[list[Packet], dict]:
    """Decode a capture file. Returns (ipsec-relevant packets, stats)."""
    stats = new_stats()
    out: list[Packet] = []
    with open(path, "rb") as fh:
        for i, fr in enumerate(iter_frames(fh), 1):
            p = account(stats, fr, i)
            if p is not None:
                out.append(p)
            if limit and stats["frames"] >= limit:
                break
    if stats["frames"] == 0:
        raise CaptureError("The capture contains no packets.")
    return out, stats


def read_frame(path: str, idx: int) -> Frame | None:
    with open(path, "rb") as fh:
        for i, fr in enumerate(iter_frames(fh), 1):
            if i == idx:
                return fr
    return None
