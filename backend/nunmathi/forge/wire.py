"""Byte-level builders for IKEv1/IKEv2 messages, ESP, UDP/IPv4/Ethernet and pcap files."""
from __future__ import annotations

import os
import random
import struct

from .. import constants as C


# ------------------------------------------------------------------ crypto geometry
def esp_geometry(encr: int, integ: int) -> tuple[int, int, int]:
    """(iv_len, block_len, icv_len) for an ESP transform (RFC 4303 / 4106 / 7634)."""
    if encr in (18, 19, 20):
        return 8, 4, {18: 8, 19: 12, 20: 16}[encr]
    if encr in (14, 15, 16):
        return 8, 4, {14: 8, 15: 12, 16: 16}[encr]
    if encr == 28:
        return 8, 4, 16
    icv = C.INTEG_ICV.get(integ, 0)
    if encr == 12 or encr == 23:
        return 16, 16, icv
    if encr in (2, 3):
        return 8, 8, icv
    if encr in (13, 24):
        return 8, 4, icv
    if encr == 11:
        return 0, 4, icv
    return 16, 16, icv


def ike_geometry(encr: int, integ: int) -> tuple[int, int, int]:
    """(iv_len, block_len, icv_len) of the IKEv2 SK payload."""
    return esp_geometry(encr, integ)


def pad_to(n: int, block: int) -> int:
    return n + (-n) % block


def esp_len(inner: int, encr: int, integ: int) -> int:
    iv, b, icv = esp_geometry(encr, integ)
    return 8 + iv + pad_to(inner + 2, b) + icv


# ------------------------------------------------------------------ IKEv2
def _chain(payloads: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """Serialize generic payloads; returns (first payload type, bytes)."""
    out = b""
    for i, (ptype, body) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        out += struct.pack("!BBH", nxt, 0, len(body) + 4) + body
    return (payloads[0][0] if payloads else 0), out


def transform(ttype: int, tid: int, keylen: int | None = None, last: bool = False) -> bytes:
    attrs = struct.pack("!HH", 0x800E, keylen) if keylen else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def proposal(num: int, proto: int, spi: bytes, transforms: list[tuple], last: bool = True) -> bytes:
    tb = b"".join(transform(*t, last=(i == len(transforms) - 1)) for i, t in enumerate(transforms))
    body = struct.pack("!BBB", num, proto, len(spi)) + bytes([len(transforms)]) + spi + tb
    return struct.pack("!BBH", 0 if last else 2, 0, len(body) + 4) + body


def sa_payload(props: list[bytes]) -> bytes:
    return b"".join(props)


def ike_transforms(p: dict, ke: int | None = None) -> list[tuple]:
    t = [(1, p["ike_encr"], p.get("ike_keylen")), (2, p["ike_prf"])]
    if p["ike_encr"] not in C.AEAD_ENCR:
        t.append((3, p["ike_integ"]))
    t.append((4, ke if ke is not None else p["ike_group"]))
    for i, g in enumerate(p.get("addke", [])):
        t.append((6 + i, g))
    return t


def notify(ntype: int, data: bytes = b"", proto: int = 0, spi: bytes = b"") -> bytes:
    return struct.pack("!BBH", proto, len(spi), ntype) + spi + data


def ke_payload(group: int, size: int | None = None) -> bytes:
    return struct.pack("!HH", group, 0) + os.urandom(size if size is not None else C.KE_SIZE.get(group, 64))


def ike_header(ispi: bytes, rspi: bytes, nxt: int, exch: int, flags: int, msgid: int, length: int,
               version: int = 0x20) -> bytes:
    return ispi + rspi + struct.pack("!BBBBII", nxt, version, exch, flags, msgid, length)


def ikev2_message(ispi, rspi, exch, flags, msgid, payloads) -> bytes:
    first, body = _chain(payloads)
    return ike_header(ispi, rspi, first, exch, flags, msgid, 28 + len(body)) + body


def sk_body(plain_len: int, encr: int, integ: int) -> bytes:
    iv, b, icv = ike_geometry(encr, integ)
    return os.urandom(iv + pad_to(plain_len + 1, b) + icv)


def ikev2_sk_message(ispi, rspi, exch, flags, msgid, first_inner: int, plain_len: int, encr, integ) -> bytes:
    body = sk_body(plain_len, encr, integ)
    pl = struct.pack("!BBH", first_inner, 0, len(body) + 4) + body
    return ike_header(ispi, rspi, 46, exch, flags, msgid, 28 + len(pl)) + pl


def ikev2_skf_messages(ispi, rspi, exch, flags, msgid, first_inner, plain_len, encr, integ, frag=560):
    n = max(1, -(-plain_len // frag))
    out = []
    for i in range(n):
        part = min(frag, plain_len - i * frag)
        body = struct.pack("!HH", i + 1, n) + sk_body(part, encr, integ)
        pl = struct.pack("!BBH", first_inner if i == 0 else 0, 0, len(body) + 4) + body
        out.append(ike_header(ispi, rspi, 53, exch, flags, msgid, 28 + len(pl)) + pl)
    return out


# ------------------------------------------------------------------ IKEv1
def v1_attr(a: int, v: int) -> bytes:
    if v < 0x10000:
        return struct.pack("!HH", 0x8000 | a, v)
    raw = v.to_bytes(4, "big")
    return struct.pack("!HH", a, len(raw)) + raw


def v1_sa(transforms: list[dict]) -> bytes:
    tb = b""
    for i, t in enumerate(transforms):
        attrs = b"".join(v1_attr(a, v) for a, v in t.items())
        body = struct.pack("!BBH", i + 1, 1, 0) + attrs   # transform num, KEY_IKE, reserved
        tb += struct.pack("!BBH", 0 if i == len(transforms) - 1 else 3, 0, len(body) + 4) + body
    prop = struct.pack("!BBBB", 1, 1, 0, len(transforms)) + tb   # num, PROTO_ISAKMP, spi size 0
    prop = struct.pack("!BBH", 0, 0, len(prop) + 4) + prop
    return struct.pack("!II", 1, 1) + prop     # DOI IPsec, SIT_IDENTITY_ONLY


def ikev1_message(ispi, rspi, exch, flags, msgid, payloads) -> bytes:
    first, body = _chain(payloads)
    return ike_header(ispi, rspi, first, exch, flags, msgid, 28 + len(body), version=0x10) + body


def ikev1_encrypted(ispi, rspi, exch, msgid, first_inner, plain_len, encr_v2, integ_v2) -> bytes:
    iv, b, _ = ike_geometry(encr_v2, integ_v2)
    body = os.urandom(pad_to(plain_len, b))   # IKEv1: IV is implicit, no ICV
    return ike_header(ispi, rspi, first_inner, exch, 0x01, msgid, 28 + len(body), version=0x10) + body


# ------------------------------------------------------------------ IP / UDP / Ethernet / pcap
def ip_checksum(h: bytes) -> int:
    s = sum(struct.unpack("!%dH" % (len(h) // 2), h))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes, ident: int, ttl: int = 64) -> bytes:
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, ttl, proto, 0, src, dst)
    h = h[:10] + struct.pack("!H", ip_checksum(h)) + h[12:]
    return h + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ether(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + payload


def fake_inner_ip(length: int, rng: random.Random) -> bytes:
    """A plausible inner IPv4 packet (used only for ESP-NULL, where it is visible on the wire)."""
    length = max(length, 28)
    body = bytes(rng.getrandbits(8) for _ in range(length - 20))
    return ipv4(bytes([10, 1, 0, 5]), bytes([10, 2, 0, 9]), 17, body, rng.getrandbits(16))


class PcapWriter:
    def __init__(self, path: str, linktype: int = 1):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        self.count = 0

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, usec - 1000000
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        self.count += 1

    def close(self) -> None:
        self.fh.close()
