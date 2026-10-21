"""Train the traffic model once and write it where the PyInstaller spec picks it up (build/model/traffic.pkl)."""
import os
import pickle
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from nunmathi import traffic  # noqa: E402

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "build", "model", "traffic.pkl")
os.makedirs(os.path.dirname(out), exist_ok=True)
m = traffic.train()
with open(out, "wb") as fh:
    pickle.dump(m, fh)
print("model", out, "accuracy", m.card["test_accuracy"])
