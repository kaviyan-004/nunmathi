"""IKEv1 / IKEv2 header and cleartext-payload dissector.

Only cleartext parts are parsed (IKE_SA_INIT, IKEv1 Main/Aggressive Mode first
messages). Encrypted payloads (SK / IKEv1 encrypted flag) are recorded as
opaque with their length, which the session analyzer uses for size inference.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import constants as C


@dataclass
class Transform:
    ttype: int
    tid: int
    keylen: int | None = None

    def label(self) -> str:
        table = {1: C.ENCR, 2: C.PRF, 3: C.INTEG, 4: C.KE, 5: {0: "NO_ESN", 1: "ESN"}}.get(self.ttype)
        if self.ttype >= 6:
            table = C.KE
        name = (table or {}).get(self.tid, f"#{self.tid}")
        return f"{name}_{self.keylen}" if self.keylen else name

    def to_dict(self) -> dict:
        return {"type": C.TRANSFORM_TYPE.get(self.ttype, str(self.ttype)), "id": self.tid,
                "keylen": self.keylen, "name": self.label()}


@dataclass
class Proposal:
    num: int
    protocol: int
    spi: str
    transforms: list[Transform] = field(default_factory=list)

    def of(self, ttype: int) -> list[Transform]:
        return [t for t in self.transforms if t.ttype == ttype]

    def to_dict(self) -> dict:
        return {"num": self.num, "protocol": C.PROTOCOL_ID.get(self.protocol, str(self.protocol)),
                "spi": self.spi, "transforms": [t.to_dict() for t in self.transforms]}


@dataclass
class IKEMessage:
    version: int                 # 1 or 2
    ispi: str
    rspi: str
    exchange: int
    exchange_name: str
    flags: int
    msgid: int
    length: int
    initiator: bool
    response: bool
    encrypted: bool = False
    payloads: list[dict] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)
    ke_group: int | None = None
    ke_len: int | None = None
    notifies: list[int] = field(default_factory=list)
    vendor_ids: list[str] = field(default_factory=list)
    sk_len: int = 0              # length of the SK / encrypted body
    fragment: tuple[int, int] | None = None   # (number, total) for SKF
    v1_auth: int | None = None
    v1_life: dict = field(default_factory=dict)
    identities: list[str] = field(default_factory=list)
    cleartext_hash: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("proposals",)}
        d["proposals"] = [p.to_dict() for p in self.proposals]
        d["notify_names"] = [C.NOTIFY.get(n, str(n)) for n in self.notifies]
        d["vendor_names"] = [vendor_name(v) for v in self.vendor_ids]
        return d


def vendor_name(vid_hex: str) -> str:
    for k, v in C.VENDOR_IDS.items():
        if vid_hex.startswith(k):
            return v
    return "unknown"


class IKEParseError(ValueError):
    pass


def parse(data: bytes) -> IKEMessage:
    if len(data) < 28:
        raise IKEParseError("shorter than IKE header")
    ispi, rspi = data[0:8].hex(), data[8:16].hex()
    nxt, ver, exch, flags = data[16], data[17], data[18], data[19]
    msgid, length = struct.unpack("!II", data[20:28])
    major = ver >> 4
    if major == 2:
        m = IKEMessage(2, ispi, rspi, exch, C.EXCHANGE_V2.get(exch, f"#{exch}"), flags, msgid, length,
                       initiator=bool(flags & 0x08), response=bool(flags & 0x20))
        try:
            _walk_v2(m, nxt, data[28:length if length <= len(data) else len(data)])
        except (struct.error, IndexError) as e:
            m.error = f"truncated payload: {e}"
        return m
    if major == 1:
        m = IKEMessage(1, ispi, rspi, exch, C.EXCHANGE_V1.get(exch, f"#{exch}"), flags, msgid, length,
                       initiator=rspi == "0" * 16, response=rspi != "0" * 16, encrypted=bool(flags & 0x01))
        if m.encrypted:
            m.sk_len = max(0, min(length, len(data)) - 28)
            m.payloads.append({"type": "Encrypted", "length": m.sk_len})
        else:
            try:
                _walk_v1(m, nxt, data[28:min(length, len(data))])
            except (struct.error, IndexError) as e:
                m.error = f"truncated payload: {e}"
        return m
    raise IKEParseError(f"unsupported IKE major version {major}")


# ------------------------------------------------------------------ IKEv2
def _walk_v2(m: IKEMessage, nxt: int, body: bytes) -> None:
    off = 0
    while nxt and off + 4 <= len(body):
        ptype = nxt
        nxt, _crit, plen = body[off], body[off + 1], struct.unpack("!H", body[off + 2:off + 4])[0]
        if plen < 4:
            m.error = "bad payload length"
            return
        pdata = body[off + 4:off + plen]
        entry = {"type": C.PAYLOAD_V2.get(ptype, f"#{ptype}"), "length": plen}
        if ptype == 33:
            m.proposals = _parse_sa_v2(pdata)
            entry["proposals"] = len(m.proposals)
        elif ptype == 34:
            m.ke_group = struct.unpack("!H", pdata[0:2])[0]
            m.ke_len = len(pdata) - 4
            entry["group"] = C.KE.get(m.ke_group, str(m.ke_group))
            entry["data_len"] = m.ke_len
        elif ptype == 41:
            ntype = struct.unpack("!H", pdata[2:4])[0]
            m.notifies.append(ntype)
            entry["notify"] = C.NOTIFY.get(ntype, str(ntype))
            if ntype == 17 and len(pdata) >= 4 + pdata[1] + 2:   # INVALID_KE_PAYLOAD carries wanted group
                entry["wanted_group"] = struct.unpack("!H", pdata[4 + pdata[1]:6 + pdata[1]])[0]
        elif ptype == 43:
            m.vendor_ids.append(pdata.hex())
            entry["vendor"] = vendor_name(pdata.hex())
        elif ptype in (46, 53):
            m.encrypted = True
            m.sk_len = plen - 4
            if ptype == 53:
                m.fragment = struct.unpack("!HH", pdata[0:4])
                entry["fragment"] = list(m.fragment)
            m.payloads.append(entry)
            return  # everything after SK is inside the ciphertext
        m.payloads.append(entry)
        off += plen


def _parse_sa_v2(data: bytes) -> list[Proposal]:
    props, off = [], 0
    while off + 8 <= len(data):
        last, plen = data[off], struct.unpack("!H", data[off + 2:off + 4])[0]
        num, proto, spisize, ntrans = data[off + 4], data[off + 5], data[off + 6], data[off + 7]
        spi = data[off + 8:off + 8 + spisize].hex()
        p = Proposal(num, proto, spi)
        toff = off + 8 + spisize
        for _ in range(ntrans):
            tlen = struct.unpack("!H", data[toff + 2:toff + 4])[0]
            ttype, tid = data[toff + 4], struct.unpack("!H", data[toff + 6:toff + 8])[0]
            keylen = None
            aoff = toff + 8
            while aoff + 4 <= toff + tlen:
                af, av = struct.unpack("!HH", data[aoff:aoff + 4])
                if af & 0x8000:
                    if af & 0x7FFF == 14:
                        keylen = av
                    aoff += 4
                else:
                    aoff += 4 + av
            p.transforms.append(Transform(ttype, tid, keylen))
            toff += max(tlen, 8)
        props.append(p)
        if last == 0 or plen < 8:
            break
        off += plen
    return props


# ------------------------------------------------------------------ IKEv1
def _walk_v1(m: IKEMessage, nxt: int, body: bytes) -> None:
    off = 0
    while nxt and off + 4 <= len(body):
        ptype = nxt
        nxt, plen = body[off], struct.unpack("!H", body[off + 2:off + 4])[0]
        if plen < 4:
            m.error = "bad payload length"
            return
        pdata = body[off + 4:off + plen]
        entry = {"type": C.PAYLOAD_V1.get(ptype, f"#{ptype}"), "length": plen}
        if ptype == 1:
            _parse_sa_v1(m, pdata)
            entry["proposals"] = len(m.proposals)
        elif ptype == 4:
            m.ke_len = len(pdata)
            entry["data_len"] = m.ke_len
        elif ptype == 5 and len(pdata) >= 4:   # cleartext identity (Aggressive Mode)
            idt = pdata[0]
            raw = pdata[4:]
            if idt == 1 and len(raw) == 4:
                ident = ".".join(str(b) for b in raw)
            else:
                ident = raw.decode("ascii", "replace")
            entry["id_type"] = {1: "IPV4_ADDR", 2: "FQDN", 3: "USER_FQDN", 9: "DER_ASN1_DN", 11: "KEY_ID"}.get(idt, idt)
            entry["identity"] = ident
            m.identities.append(ident)
        elif ptype == 8:
            entry["hash_len"] = len(pdata)
            m.cleartext_hash = True
        elif ptype == 11:
            ntype = struct.unpack("!H", pdata[6:8])[0] if len(pdata) >= 8 else 0
            m.notifies.append(ntype)
            entry["notify"] = ntype
        elif ptype == 13:
            m.vendor_ids.append(pdata.hex())
            entry["vendor"] = vendor_name(pdata.hex())
        m.payloads.append(entry)
        off += plen
    # IKEv1 KE has no group field; infer group from the SA or from the KE size
    if m.ke_group is None and m.ke_len:
        for g, size in C.KE_SIZE.items():
            if size == m.ke_len and g in (1, 2, 5, 14, 15, 16):
                m.ke_group = g
                break


def _parse_sa_v1(m: IKEMessage, data: bytes) -> None:
    # DOI(4) + Situation(4), then Proposal payloads
    off = 8
    while off + 8 <= len(data):
        pnext, plen = data[off], struct.unpack("!H", data[off + 2:off + 4])[0]
        num, proto, spisize, ntrans = data[off + 4], data[off + 5], data[off + 6], data[off + 7]
        spi = data[off + 8:off + 8 + spisize].hex()
        toff = off + 8 + spisize
        for _ in range(ntrans):
            tlen = struct.unpack("!H", data[toff + 2:toff + 4])[0]
            p = Proposal(num, proto, spi)
            aoff, enc, hsh, grp, keylen = toff + 8, None, None, None, None
            ltype = None
            while aoff + 4 <= toff + tlen:
                af, av = struct.unpack("!HH", data[aoff:aoff + 4])
                if af & 0x8000:
                    a, val = af & 0x7FFF, av
                    aoff += 4
                else:
                    a = af
                    val = int.from_bytes(data[aoff + 4:aoff + 4 + av], "big")
                    aoff += 4 + av
                if a == 1:
                    enc = val
                elif a == 2:
                    hsh = val
                elif a == 3:
                    m.v1_auth = val if m.v1_auth is None else m.v1_auth
                elif a == 4:
                    grp = val
                elif a == 11:
                    ltype = val
                elif a == 12 and ltype is not None:
                    m.v1_life["seconds" if ltype == 1 else "kilobytes"] = val
                elif a == 14:
                    keylen = val
            if enc is not None:
                p.transforms.append(Transform(1, C.V1_TO_V2_ENCR.get(enc, 1000 + enc), keylen))
            if hsh is not None:
                p.transforms.append(Transform(2, C.V1_TO_V2_PRF.get(hsh, 1000 + hsh)))
            if grp is not None:
                p.transforms.append(Transform(4, grp))
                if m.ke_group is None:
                    m.ke_group = grp
            m.proposals.append(p)
            toff += max(tlen, 8)
        if pnext == 0 or plen < 8:
            break
        off += plen
