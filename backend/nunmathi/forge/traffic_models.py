"""Stochastic generators of inner (pre-encryption) packet sequences for five application classes.

Each generator returns a list of (t_offset_seconds, direction, inner_ip_length) where
direction is "up" (initiator -> responder) or "down". Parameters are randomized per call
so that repeated calls yield different realizations of the same class.
"""
from __future__ import annotations

import random

CLASSES = ["voip", "video", "web", "chat", "email"]

MTU_PAYLOAD = 1400   # inner packets are clamped so that the ESP packet fits a 1500 MTU


def _ack(rng: random.Random) -> int:
    return rng.choice([40, 52, 52, 52, 64])


def voip(rng: random.Random, dur: float) -> list:
    codec = rng.choice(["g711", "g729", "opus", "opus", "cbr"])
    ptime = rng.choice([0.02, 0.02, 0.02, 0.03]) if codec != "cbr" else rng.choice([0.01, 0.02, 0.02, 0.03, 0.04])
    cbr = rng.randint(60, 340)                           # other constant-bitrate codecs (G.722, AMR, iLBC, ...)
    size = {"g711": lambda: 200, "g729": lambda: 60, "opus": lambda: rng.randint(95, 165), "cbr": lambda: cbr}[codec]
    out = []
    for direction, phase in (("up", 0.0), ("down", rng.uniform(0, ptime))):
        t = phase
        talking = True
        next_switch = rng.expovariate(1 / 4.0)
        while t < dur:
            if t > next_switch:
                talking = not talking
                next_switch = t + rng.expovariate(1 / (4.0 if talking else 1.5))
            if talking or rng.random() < 0.06:          # comfort noise while silent
                out.append((t, direction, size() if talking else rng.randint(41, 60)))
            t += ptime + rng.gauss(0, 0.0015)
        # RTCP every ~5 s
        for k in range(int(dur // 5)):
            out.append((k * 5 + rng.uniform(0, 1), direction, rng.randint(80, 120)))
    return out


def video(rng: random.Random, dur: float) -> list:
    if rng.random() < 0.4:
        return _live_video(rng, dur)
    bitrate = rng.choice([0.8e6, 1.2e6, 2e6, 3e6])      # bits/s (kept modest so demo captures stay small)
    seg = rng.uniform(2.0, 4.0)
    ack_every = rng.choice([1, 2, 2])
    out, t = [], rng.uniform(0, 0.5)
    while t < dur:
        out.append((t, "up", rng.randint(320, 700)))   # segment request
        nbytes = bitrate * seg / 8 * rng.uniform(0.7, 1.3)
        n = int(nbytes / MTU_PAYLOAD)
        rate = rng.uniform(900, 3000)                  # packets/s during the burst
        tt = t + rng.uniform(0.02, 0.08)
        for i in range(n):
            out.append((tt, "down", MTU_PAYLOAD if rng.random() < 0.97 else rng.randint(600, 1400)))
            if i % ack_every == ack_every - 1:
                out.append((tt + 0.0004, "up", _ack(rng)))
            tt += rng.expovariate(rate)
        t += seg * rng.uniform(0.9, 1.1)
    return out


def _live_video(rng: random.Random, dur: float) -> list:
    """Real-time video over UDP/RTP (conferencing, live streams): one packet burst per frame, no ACKs."""
    fps = rng.choice([15, 24, 25, 30, 30, 60])
    bitrate = rng.uniform(0.4e6, 4e6)
    pkt = rng.choice([1100, 1200, 1250, 1300, MTU_PAYLOAD]) if rng.random() < 0.7 else None
    gop = rng.uniform(1.0, 5.0)
    out, t, next_key = [], rng.uniform(0, 0.1), 0.0
    while t < dur:
        frame = bitrate / fps / 8 * rng.uniform(0.6, 1.4)
        if t >= next_key:
            frame *= rng.uniform(4, 10)
            next_key = t + gop
        n = max(1, round(frame / (pkt or 1200)))
        tt = t
        for i in range(n):
            size = pkt or rng.randint(900, MTU_PAYLOAD)
            out.append((tt, "down", size if i < n - 1 or pkt else rng.randint(200, size)))
            tt += rng.uniform(0.0001, 0.002)
        t += 1 / fps + rng.gauss(0, 0.002)
    for k in range(int(dur)):                            # RTCP receiver reports
        if rng.random() < 0.7:
            out.append((k + rng.uniform(0, 1), "up", rng.randint(60, 120)))
    return out


def web(rng: random.Random, dur: float) -> list:
    tls = rng.random() < 0.7
    ack_every = rng.choice([1, 2, 2])
    rate = rng.choice([1500, 3000, 8000])               # download packets/s (WAN .. LAN)
    think = (rng.uniform(0.5, 3.0), rng.uniform(4.0, 12.0))
    out, t = [], rng.uniform(0, 1)
    while t < dur:
        # TCP handshake, then optional TLS handshake
        out += [(t, "up", 60), (t + 0.02, "down", 60), (t + 0.021, "up", 52)]
        tt = t + 0.03
        if tls:
            out += [(tt, "up", rng.randint(250, 600)), (tt + 0.04, "down", MTU_PAYLOAD),
                    (tt + 0.041, "down", rng.randint(900, 1400)), (tt + 0.08, "up", rng.randint(100, 180))]
            tt += 0.1
        for _obj in range(rng.randint(3, 25) if tls else rng.randint(1, 4)):
            out.append((tt, "up", rng.randint(400, 950) if tls else rng.randint(120, 400)))
            n = max(1, int(rng.paretovariate(1.2) * 3)) if tls else int(rng.uniform(2e3, 3e5) / MTU_PAYLOAD) + 1
            n = min(n, 400)
            t2 = tt + rng.uniform(0.002, 0.15)
            for i in range(n):
                last = i == n - 1
                out.append((t2, "down", rng.randint(200, 1400) if last else MTU_PAYLOAD))
                if i % ack_every == ack_every - 1:
                    out.append((t2 + 0.0005, "up", _ack(rng)))
                t2 += rng.expovariate(rate)
            tt = t2 + rng.uniform(0.005, 0.2)
        t = tt + rng.uniform(*think)                    # think time
    return out


def chat(rng: random.Random, dur: float) -> list:
    out = []
    t = rng.uniform(0, 2)
    while t < dur:
        d = rng.choice(["up", "down"])
        if rng.random() < 0.4:                          # typing indicator
            out.append((t, d, rng.randint(90, 120)))
            t += rng.uniform(0.5, 3)
        out.append((t, d, rng.randint(120, 480) if rng.random() < 0.9 else rng.randint(600, 1400)))
        out.append((t + rng.uniform(0.03, 0.1), "down" if d == "up" else "up", rng.randint(60, 90)))  # receipt
        t += rng.expovariate(1 / rng.uniform(1.5, 5.0))
    hb = rng.uniform(10, 30)
    for k in range(int(dur // hb)):
        tk = k * hb + rng.uniform(0, 0.5)
        out += [(tk, "up", rng.randint(60, 80)), (tk + 0.05, "down", rng.randint(60, 80))]
    return out


def email(rng: random.Random, dur: float) -> list:
    out, t = [], rng.uniform(0, 1)
    while t < dur:
        if rng.random() < 0.5:                           # SMTP submit with attachment: upload heavy
            out += [(t, "up", rng.randint(80, 200)), (t + 0.05, "down", rng.randint(80, 200))]
            n = int(rng.lognormvariate(3.5, 1.0))
            tt = t + 0.15
            for i in range(min(n, 900)):
                out.append((tt, "up", MTU_PAYLOAD))
                if i % 2:
                    out.append((tt + 0.001, "down", _ack(rng)))
                tt += rng.expovariate(700)
            out.append((tt + 0.05, "down", rng.randint(90, 160)))
        else:                                             # IMAP fetch
            out.append((t, "up", rng.randint(90, 160)))
            n = int(rng.lognormvariate(2.5, 1.0))
            tt = t + 0.05
            for i in range(min(n, 500)):
                out.append((tt, "down", MTU_PAYLOAD if i < n - 1 else rng.randint(100, 1400)))
                if i % 2:
                    out.append((tt + 0.001, "up", _ack(rng)))
                tt += rng.expovariate(900)
        # between transfers the session is mostly silent: IMAP IDLE refreshes and TCP keepalives are
        # minutes apart, so an occasional short exchange (or a new-mail notification) at most
        gap = rng.uniform(4, 15)
        if rng.random() < 0.25:
            k = t + rng.uniform(1, gap)
            out += [(k, "down", rng.randint(60, 140)), (k + 0.04, "up", rng.randint(52, 90))]
        t += gap
    return out


GENERATORS = {"voip": voip, "video": video, "web": web, "chat": chat, "email": email}


def generate(cls: str, rng: random.Random, dur: float) -> list:
    pkts = [p for p in GENERATORS[cls](rng, dur) if 0 <= p[0] < dur]
    pkts.sort(key=lambda p: p[0])
    return pkts
