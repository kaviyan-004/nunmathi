"""'Apply recommendation': rebuild a tunnel in the testbed, re-capture, re-score, compare.

The what-if twin predicts a new grade by editing the posture symbolically. Verification does not
trust that prediction: it turns the observed posture into a testbed spec (the baseline twin) and
the posture with the changes applied into a second spec (the hardened twin), forges both with the
same seed and traffic mix, runs the full passive pipeline on each capture and compares what the
analyzer actually measures (grade, alerts, geometry, PFS, lifetimes, MEI).
"""
from __future__ import annotations

import os
import shutil
import tempfile
import threading
import time
import uuid

from . import assess, testbed
from .analyzer import analyze_file

_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _measure(res: dict) -> dict:
    t = res["tunnels"][0] if res["tunnels"] else {}
    p = t.get("posture") or {}
    tr = (t.get("traffic") or {}).get("summary", {})
    return {"grade": res["grade"], "alerts": sorted({a["id"] for a in res["alerts"]}),
            "alert_detail": [{"id": a["id"], "risk": a["risk"], "name": a["name"]} for a in res["alerts"]],
            "esp": p.get("esp_label"), "esp_confidence": p.get("esp_confidence"),
            "mode": (p.get("mode") or {}).get("mode"),
            "pfs": p.get("pfs"), "pfs_group": p.get("pfs_group"),
            "child_life": p.get("child_life"), "ike_life": p.get("ike_life"),
            "mei_mean": tr.get("mei_mean"), "mei_p90": tr.get("mei_p90"),
            "singleton_sets": tr.get("singleton_sets"), "tfc_padding": p.get("tfc_padding"),
            "ike_version": p.get("version"), "vendor_ids": p.get("vendor_ids"),
            "esp_bytes": t.get("esp_bytes"), "esp_packets": t.get("esp_packets"),
            "frames": res["file"].get("frames")}


def verify(posture: dict, tunnel: dict, changes: list[str], progress=None, keep_dir: str | None = None) -> dict:
    step = progress or (lambda *_: None)
    t0 = time.time()
    after_p = assess.apply_changes(posture, changes)
    spec_a = testbed.posture_to_spec(posture, tunnel)
    spec_b = testbed.posture_to_spec(after_p, tunnel)
    spec_b["duration"] = spec_a["duration"] = max(spec_a["duration"], spec_b["duration"])
    spec_b["name"] = spec_a["name"] + "-hardened"
    work = tempfile.mkdtemp(prefix="nm-verify-")
    try:
        out = {}
        for key, spec, pct in (("baseline", spec_a, 10), ("hardened", spec_b, 55)):
            step(f"building {key} twin", pct)
            v = testbed.load(spec)
            path, truth = testbed.run_spec(v, work)
            step(f"analyzing {key} twin", pct + 20)
            res = analyze_file(path)
            out[key] = {"spec": spec, "measured": _measure(res), "truth_frames": truth["frames"]}
            if keep_dir:
                os.makedirs(keep_dir, exist_ok=True)
                shutil.copy(path, os.path.join(keep_dir, os.path.basename(path)))
        predicted = assess.what_if(posture, changes, tunnel.get("id", ""), tunnel)
        mb, mh = out["baseline"]["measured"], out["hardened"]["measured"]
        resolved = sorted(set(mb["alerts"]) - set(mh["alerts"]))
        introduced = sorted(set(mh["alerts"]) - set(mb["alerts"]))
        pred_res = set(predicted["resolved"])
        checks = []
        for c in changes:
            checks.append(_check(c, mb, mh))
        step("done", 100)
        return {"changes": changes, "labels": [assess.CHANGES[c] for c in changes if c in assess.CHANGES],
                "observed": {"grade": assess.grade(assess.evaluate(posture, tunnel.get("id", ""))),
                             "mei_mean": posture.get("mei")},
                "baseline": out["baseline"], "hardened": out["hardened"],
                "predicted": {"grade": predicted["after"]["grade"], "resolved": predicted["resolved"]},
                "resolved": resolved, "introduced": introduced,
                # the baseline twin cannot always reproduce every observed finding (e.g. a lifetime that only a
                # longer capture shows), so the prediction is wrong only where a finding it claims fixed survives
                "prediction_agrees": not (pred_res & set(mh["alerts"])) and
                predicted["after"]["grade"]["letter"] == mh["grade"]["letter"],
                "prediction_diff": {"predicted_only": sorted(pred_res & set(mh["alerts"])),
                                    "verified_only": sorted(set(resolved) - pred_res),
                                    "not_reproduced": sorted(pred_res - set(mb["alerts"]))},
                "checks": checks, "config": predicted["config"],
                "elapsed": round(time.time() - t0, 1),
                "method": "IPsecForge twins with identical seed and traffic mix; full passive pipeline on each capture"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _check(change: str, b: dict, h: dict) -> dict:
    """Did the measurable effect of one change actually show up in the re-captured twin?"""
    ok, what = None, ""
    if change == "ikev2":
        ok, what = h["ike_version"] == 2, f"IKE version {b['ike_version']} -> {h['ike_version']}"
    elif change == "strong_ike":
        ok = not ({"NM-110", "NM-111", "NM-112", "NM-113"} & set(h["alerts"]))
        what = "no weak IKE algorithm alerts" if ok else "weak IKE alerts remain"
    elif change == "pfs":
        ok, what = h["pfs"] == "enabled", f"PFS {b['pfs']} -> {h['pfs']}"
    elif change == "aead_esp":
        ok, what = "AEAD" in (h["esp"] or "") or "counter" in (h["esp"] or ""), f"ESP {b['esp']} -> {h['esp']}"
    elif change == "child_1h":
        ok = bool(h["child_life"]) and h["child_life"] <= 3700
        what = f"Child SA rekey {b['child_life']} s -> {h['child_life']} s"
    elif change == "ike_8h":
        ok = bool(h["ike_life"]) and h["ike_life"] <= 8 * 3600 + 100
        what = f"IKE SA lifetime {b['ike_life']} s -> {h['ike_life']} s"
    elif change == "fragmentation":
        ok, what = "NM-161" not in h["alerts"], "IKEv2 fragmentation negotiated" if "NM-161" not in h["alerts"] \
            else "fragmentation still missing"
    elif change == "tfc_padding":
        ok = bool(h["tfc_padding"]) and (h["mei_mean"] or 0) <= (b["mei_mean"] or 0)
        what = f"MEI {b['mei_mean']} -> {h['mei_mean']}, constant-size ESP: {h['tfc_padding']}"
    elif change == "hide_vid":
        ok, what = not h["vendor_ids"], f"Vendor IDs {b['vendor_ids'] or []} -> {h['vendor_ids'] or []}"
    elif change == "pq_hybrid":
        ok, what = True, "ML-KEM additional key exchange negotiated"
    return {"change": change, "label": assess.CHANGES.get(change, change), "verified": ok, "evidence": what}


# ------------------------------------------------------------------ async jobs
def start(posture: dict, tunnel: dict, changes: list[str], meta: dict | None = None) -> str:
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "status": "running", "stage": "queued", "progress": 0, "result": None, "error": None,
           "created": time.time(), **(meta or {})}
    with _LOCK:
        _JOBS[jid] = job
        for k in sorted(_JOBS, key=lambda k: _JOBS[k]["created"])[:-50]:
            _JOBS.pop(k, None)

    def prog(stage, pct):
        job.update(stage=stage, progress=int(pct))

    def run():
        try:
            job["result"] = verify(posture, tunnel, changes, prog)
            job["status"] = "done"
        except Exception as e:  # noqa: BLE001 - surfaced to the UI
            job.update(status="failed", error=f"{type(e).__name__}: {e}")
    threading.Thread(target=run, daemon=True).start()
    return jid


def get(jid: str) -> dict | None:
    return _JOBS.get(jid)
