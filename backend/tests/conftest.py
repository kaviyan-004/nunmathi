"""Shared fixtures. NUNMATHI_DATA points at a temp dir before any nunmathi module is imported."""
import os
import shutil
import sys
import tempfile

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

_DATA = tempfile.mkdtemp(prefix="nunmathi-test-")
_models = os.path.join(HERE, "..", "data", "models")
if os.path.isdir(_models):  # reuse the trained model instead of retraining per run
    shutil.copytree(_models, os.path.join(_DATA, "models"))
os.environ["NUNMATHI_DATA"] = _DATA

from nunmathi.analyzer import analyze_file  # noqa: E402
from nunmathi.forge.generator import forge  # noqa: E402
from nunmathi.forge.scenarios import SCENARIOS  # noqa: E402


def short(name: str, duration: int = 1500, windows: int = 4) -> dict:
    p = dict(SCENARIOS[name])
    p["duration"] = duration
    p["active_windows"] = windows
    return p


@pytest.fixture(scope="session")
def data_dir():
    yield _DATA
    shutil.rmtree(_DATA, ignore_errors=True)


@pytest.fixture(scope="session")
def forged(data_dir):
    """Short versions of every demo scenario: {name: (pcap_path, truth, result)}."""
    out = {}
    d = os.path.join(data_dir, "forged")
    os.makedirs(d, exist_ok=True)
    for name in SCENARIOS:
        path = os.path.join(d, f"{name}.pcap")
        # hardened-pq rekeys its Child SA hourly; give it long enough to observe a rekey (PFS inference)
        prof = short(name, duration=5400) if name == "hardened-pq" else short(name)
        truth = forge(prof, path, None, seed=prof.get("seed", 1))
        out[name] = (path, truth, analyze_file(path))
    return out
