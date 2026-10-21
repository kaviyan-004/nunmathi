"""SHAP-style feature attributions for the traffic classifier.

Shapley values are estimated with antithetic permutation sampling (Štrumbelj & Kononenko, 2014)
against a background sample drawn from the model's training distribution (interventional
Shapley values, the same quantity shap.PermutationExplainer estimates). For each sampled feature
ordering the features of the explained window are switched in one by one over every background
row, and the change in the predicted class probability is credited to the feature switched in.

Properties that hold by construction: phi sums exactly to f(x) - E[f(background)] (efficiency),
and a feature the model never uses gets phi = 0. The estimate is Monte-Carlo, so each value
carries a standard error that is reported alongside it.
"""
from __future__ import annotations

import numpy as np

from . import traffic

N_BACKGROUND = 24
N_PERMUTATIONS = 12       # antithetic pairs -> 24 orderings


def _background(model: traffic.TrafficModel, n: int, seed: int = 7) -> np.ndarray:
    rng = np.random.default_rng(seed)
    Z = model.nn_train[rng.choice(len(model.nn_train), size=min(n, len(model.nn_train)), replace=False)]
    return Z * model.sd + model.mu


def shapley(model: traffic.TrafficModel, x: np.ndarray, cls: int, n_perm: int = N_PERMUTATIONS,
            n_bg: int = N_BACKGROUND, seed: int = 0) -> dict:
    x = np.asarray(x, dtype=float)
    d = len(x)
    bg = _background(model, n_bg)
    rng = np.random.default_rng(seed)
    perms = []
    for _ in range(n_perm):
        p = rng.permutation(d)
        perms += [p, p[::-1]]                       # antithetic pair halves the variance for monotone effects
    # rows: for each ordering, d+1 prefixes x_S (S = first k features) mixed with every background row
    rows = np.empty((len(perms), d + 1, len(bg), d))
    for i, p in enumerate(perms):
        cur = bg.copy()
        rows[i, 0] = cur
        for k, j in enumerate(p, 1):
            cur = cur.copy()
            cur[:, j] = x[j]
            rows[i, k] = cur
    P = model.clf.predict_proba(rows.reshape(-1, d))[:, cls].reshape(len(perms), d + 1, len(bg)).mean(2)
    contrib = np.zeros((len(perms), d))
    for i, p in enumerate(perms):
        contrib[i, p] = np.diff(P[i])
    phi = contrib.mean(0)
    se = contrib.std(0, ddof=1) / np.sqrt(len(perms))
    return {"phi": phi, "se": se, "base": float(P[:, 0].mean()), "fx": float(P[:, -1].mean())}


def explain_window(window: dict, top: int = 12) -> dict:
    model = traffic.get_model()
    x = np.array(window["x"], dtype=float)
    cls = traffic.CLASSES.index(window["label"])
    r = shapley(model, x, cls)
    order = np.argsort(-np.abs(r["phi"]))
    feats = [{"feature": traffic.FEATURE_NAMES[j], "value": round(float(x[j]), 4),
              "phi": round(float(r["phi"][j]), 5), "se": round(float(r["se"][j]), 5)} for j in order]
    return {"label": window["label"], "start": window["start"], "end": window["end"],
            "base_value": round(r["base"], 4), "prediction": round(r["fx"], 4),
            "sum_phi": round(float(r["phi"].sum()), 4), "features": feats[:top],
            "other_phi": round(float(sum(f["phi"] for f in feats[top:])), 5)}


def explain_tunnel(windows: list[dict], max_windows: int = 10) -> dict:
    """Mean |phi| per feature over a sample of windows (global importance for this tunnel)."""
    ws = [w for w in windows if w.get("x")]
    if not ws:
        return {"windows": 0, "features": []}
    if len(ws) > max_windows:
        idx = np.linspace(0, len(ws) - 1, max_windows).round().astype(int)
        ws = [ws[i] for i in sorted(set(idx))]
    model = traffic.get_model()
    acc = np.zeros(len(traffic.FEATURE_NAMES))
    signed: dict[str, np.ndarray] = {}
    for w in ws:
        cls = traffic.CLASSES.index(w["label"])
        r = shapley(model, np.array(w["x"]), cls, n_perm=6)
        acc += np.abs(r["phi"])
        signed.setdefault(w["label"], np.zeros_like(acc))
        signed[w["label"]] += r["phi"]
    acc /= len(ws)
    order = np.argsort(-acc)
    return {"windows": len(ws), "method": "antithetic permutation Shapley, 24-row background",
            "features": [{"feature": traffic.FEATURE_NAMES[j], "mean_abs_phi": round(float(acc[j]), 5)}
                         for j in order[:15]],
            "per_class": {c: [{"feature": traffic.FEATURE_NAMES[j], "phi": round(float(v[j] / len(ws)), 5)}
                              for j in np.argsort(-np.abs(v))[:6]] for c, v in signed.items()}}
