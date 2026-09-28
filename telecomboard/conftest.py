import os
import sys
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(scope="session", autouse=True)
def seeded(tmp_path_factory):
    # Test runs never inherit real cloud credentials or mutate the demo database.
    for name in list(os.environ):
        if name.startswith(("PERMIT_", "NEO4J_", "LANGFUSE_", "OTEL_", "GOOGLE_", "SB_")):
            os.environ.pop(name)
    os.environ["SB_DEV_ENDPOINTS"] = "1"
    os.environ["SB_DATA_DIR"] = str(tmp_path_factory.mktemp("sbdata"))
    from switchboard.datagen import seed

    seed(400)
    return Path(os.environ["SB_DATA_DIR"])


@pytest.fixture(autouse=True)
def isolated_data(seeded, tmp_path, monkeypatch):
    """Each test starts with the same facts, regardless of earlier grants or writes."""
    from switchboard import auth, core, legacy, policy

    target = tmp_path / "data"
    shutil.copytree(seeded, target)
    monkeypatch.setenv("SB_DATA_DIR", str(target))
    auth._priv = None
    core._clock_offset = 0
    policy._pdp = None
    legacy._breaker.clear()
    yield
    idp = getattr(policy, "_pdp", None)
    if hasattr(idp, "_expiry_stop"):
        idp._expiry_stop.set()
    policy._pdp = None


@pytest.fixture()
def gw():
    from fastapi.testclient import TestClient

    from switchboard.gateway import _hits, app

    _hits.clear()
    return TestClient(app)


def token(gw, user):
    return {"Authorization": "Bearer " + gw.post("/dev/token", json={"user_id": user}).json()["access_token"]}


def principal(user):
    from switchboard import auth

    return auth.principal_from_token(auth.issue(user))


def all_psks() -> set[str]:
    from switchboard.core import connect
    from switchboard.datagen import fernet

    f = fernet()
    with connect("legacy") as c:
        return {f.decrypt(r[0]).decode() for r in c.execute("SELECT psk_enc FROM wln_cfg")}
