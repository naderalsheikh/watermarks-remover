"""The standalone engine worker must not import the control-plane stack."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_real_worker_inspection_without_web_or_database_imports(tmp_path):
    source = tmp_path / "synthetic.txt"
    source.write_text("Synthetic agreement for import-boundary testing.")
    output = tmp_path / "output"
    program = """
import sys, runpy
class ControlPlaneImportGuard:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "app.main" or fullname.split(".")[0] in {"fastapi", "sqlalchemy", "alembic"}:
            raise AssertionError("worker imported control-plane module: " + fullname)
sys.meta_path.insert(0, ControlPlaneImportGuard())
sys.argv = ["app.worker", "run-job", "--kind", "inspect", "--input", sys.argv[1], "--output-dir", sys.argv[2]]
runpy.run_module("app.worker", run_name="__main__")
"""
    env = {**os.environ, "PYTHONPATH": str(REPO / "service")}
    result = subprocess.run(
        [sys.executable, "-c", program, str(source), str(output)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads((output / "result.json").read_bytes())
    assert payload["status"] == "done", payload
    assert isinstance(payload["result"]["findings"], list)


def test_public_app_factory_retains_original_identity(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "service"))
    from app import create_app
    from app.main import create_app as original

    assert create_app is original
