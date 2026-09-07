"""Test configuration for quarantined research harnesses."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "research" / "harnesses"))
sys.path.insert(0, str(ROOT / "service" / "scripts"))
sys.path.insert(0, str(ROOT / "service" / "app"))
