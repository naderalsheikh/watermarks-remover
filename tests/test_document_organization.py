"""Organization is mutable, audited metadata; released evidence stays immutable."""

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "service"), str(ROOT / "service/scripts")]

from app.config import Config
from app.db import make_engine, make_session_factory
from app.main import create_app
from app.models import MatterAcl
from fastapi.testclient import TestClient


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("COUNSELCLEAR_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("COUNSELCLEAR_LOCAL_PASSWORD", "synthetic-org-password")
    monkeypatch.setenv("COUNSELCLEAR_TSA_URL", "off")
    root = tmp_path / "data"
    with TestClient(create_app(root)) as c:
        assert (
            c.post("/v1/auth/login", json={"password": "synthetic-org-password"}).status_code == 200
        )
        m = c.post(
            "/v1/matters",
            json={"name": "Acquisition", "client_name": "Acme", "matter_number": "A-100"},
        ).json()
        yield c, m, root


def upload(c, matter, name="agreement.docx"):
    data = (Path(__file__).parent / "fixtures/legal/spa.docx").read_bytes()
    r = c.post(f"/v1/matters/{matter}/documents", files={"file": (name, data)})
    assert r.status_code == 200, r.text
    return r.json()


def organize(c, m, d, parent=None, category="Agreement", version=0):
    return c.put(
        f"/v1/matters/{m}/documents/{d}/organization",
        json={"category": category, "previous_revision_id": parent, "expected_version": version},
    )


def test_matter_search_close_reopen_and_stale_edit(workspace):
    c, m, _ = workspace
    for q in ("acme", "A-100", "acquisition"):
        assert c.get("/v1/matters", params={"q": q}).json()["total"] == 1
    assert c.get("/v1/matters", params={"q": "%"}).json()["total"] == 0
    path = f"/v1/matters/{m['id']}/organization"
    body = {
        "client_name": "Acme",
        "matter_number": "A-100",
        "status": "closed",
        "expected_version": 0,
    }
    assert c.put(path, json=body).json()["status"] == "closed"
    assert c.get("/v1/matters?status=active").json()["total"] == 0
    assert c.get("/v1/matters?status=closed").json()["total"] == 1
    assert c.put(path, json=body).status_code == 409
    # Closure labels the matter; it does not revoke upload or hide history.
    upload(c, m["id"])
    body.update(status="active", expected_version=1)
    assert c.put(path, json=body).json()["organization_version"] == 2
    audit = c.get(f"/v1/matters/{m['id']}/audit").json()
    assert audit["chain_ok"]
    assert len([e for e in audit["events"] if e["action"] == "matter.organize"]) == 2


def test_revision_graph_cycles_foreign_links_and_pagination(workspace):
    c, m, _ = workspace
    mid = m["id"]
    a, b, d = [upload(c, mid, name) for name in ("a.docx", "b.docx", "c.docx")]
    assert organize(c, mid, b["id"], a["id"]).status_code == 200
    assert organize(c, mid, d["id"], b["id"]).status_code == 200
    assert organize(c, mid, a["id"], d["id"]).status_code == 409
    assert organize(c, mid, a["id"], a["id"]).status_code == 409
    other = c.post("/v1/matters", json={"name": "Other"}).json()["id"]
    foreign = upload(c, other)
    for parent in (foreign["id"], "f" * 16):
        r = organize(c, mid, a["id"], parent)
        assert r.status_code == 422
        assert "this matter" in r.json()["detail"]
    assert organize(c, mid, b["id"], None).status_code == 409  # stale version
    r = c.get(f"/v1/matters/{mid}/documents/{b['id']}/revisions").json()
    assert r["previous"]["id"] == a["id"] and r["next"][0]["id"] == d["id"]
    assert (
        c.get(f"/v1/matters/{mid}/documents", params={"category": "Agreement", "limit": 1}).json()[
            "total"
        ]
        == 2
    )
    assert c.get(f"/v1/matters/{mid}/documents", params={"category": ""}).json()["total"] == 1
    assert (
        c.get(f"/v1/matters/{mid}/documents", params={"document_id": a["id"]}).json()["documents"][
            0
        ]["id"]
        == a["id"]
    )
    assert c.get(f"/v1/matters/{mid}/document-categories").json()["categories"] == ["", "Agreement"]
    assert organize(c, mid, b["id"], None, version=1).status_code == 200
    assert c.get(f"/v1/matters/{mid}/documents/{a['id']}/revisions").json()["next"] == []


def test_organization_cannot_rewrite_released_evidence(workspace):
    c, m, root = workspace
    d = upload(c, m["id"])
    base = f"/v1/matters/{m['id']}"
    r = c.post(
        f"{base}/documents/{d['id']}/releases", json={"profile_id": "counterparty_deal_room"}
    ).json()
    assert r["job"]["status"] == "done"
    job = r["job"]["id"]
    certificate = c.get(f"{base}/jobs/{job}/certificate").content
    manifest = c.get(f"{base}/jobs/{job}/manifest").json()
    originals = {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (root / "local").rglob("*")
        if p.is_file()
    }
    assert organize(c, m["id"], d["id"]).status_code == 200
    assert (
        c.put(
            f"{base}/organization",
            json={
                "client_name": "New label",
                "matter_number": "100",
                "status": "closed",
                "expected_version": 0,
            },
        ).status_code
        == 200
    )
    assert c.get(f"{base}/jobs/{job}/certificate").content == certificate
    assert c.get(f"{base}/jobs/{job}/manifest").json() == manifest
    assert originals == {
        str(p): hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in originals
    }
    assert c.get(f"{base}/audit").json()["chain_ok"]


def test_permission_and_input_validation(workspace):
    c, m, root = workspace
    mid = m["id"]
    d = upload(c, mid)
    assert c.post("/v1/matters", json={"name": "   "}).status_code == 422
    assert organize(c, mid, d["id"], category="x" * 81).status_code == 422
    engine = make_engine(Config(root))
    with make_session_factory(engine)() as session:
        session.query(MatterAcl).filter_by(matter_id=mid, user_id="operator", perm="admin").delete()
        session.commit()
    engine.dispose()
    assert organize(c, mid, d["id"]).status_code == 403
    assert (
        c.put(
            f"/v1/matters/{mid}/organization",
            json={
                "client_name": "",
                "matter_number": "",
                "status": "closed",
                "expected_version": 0,
            },
        ).status_code
        == 403
    )
    assert c.get(f"/v1/matters/{mid}/documents").status_code == 200
    # No grants on this ID: category and revision read paths fail closed.
    assert c.get("/v1/matters/ffffffffffffffff/document-categories").status_code == 403
    assert c.get(f"/v1/matters/ffffffffffffffff/documents/{d['id']}/revisions").status_code == 403


def test_audit_failure_rolls_back_organization_change(workspace, monkeypatch):
    import app.main as main

    c, m, _ = workspace
    original = main.append_event

    def fail_event(*args, **kwargs):
        if kwargs.get("action") == "matter.organize":
            raise RuntimeError("synthetic audit failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(main, "append_event", fail_event)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        c.put(
            f"/v1/matters/{m['id']}/organization",
            json={
                "client_name": "Changed",
                "matter_number": "X",
                "status": "closed",
                "expected_version": 0,
            },
        )
    actual = c.get(f"/v1/matters/{m['id']}").json()
    assert (actual["client_name"], actual["status"], actual["organization_version"]) == (
        "Acme",
        "active",
        0,
    )
