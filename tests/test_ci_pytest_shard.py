"""The CI shard launcher must partition real collected nodes without losing tests."""

from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from ci_pytest_shard import ShardSelection, partition_nodeids

LAUNCHER = REPO / "tools" / "ci_pytest_shard.py"


def test_partition_is_exact_ordered_and_stable_when_collection_changes():
    nodes = [f"tests/test_example.py::test_case[{i}]" for i in range(60)]
    parts = partition_nodeids(nodes, 3)
    assert all(parts)
    assert Counter(node for part in parts for node in part) == Counter(nodes)
    for part in parts:
        assert part == [node for node in nodes if node in part]
    reordered = partition_nodeids(["tests/test_new.py::test_new", *reversed(nodes)], 3)
    for old, new in zip(parts, reordered, strict=True):
        assert set(old) == set(new) - {"tests/test_new.py::test_new"}


@pytest.mark.parametrize("shard,count", [(0, 3), (4, 3), (1, 0), (1, -1)])
def test_invalid_shard_configuration_is_rejected(shard, count):
    with pytest.raises(ValueError, match="shard"):
        ShardSelection(shard, count)


def test_duplicate_collection_is_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        partition_nodeids(["test_a.py::test_a"] * 2, 3)


def test_real_collection_filters_then_partitions_without_overlap(tmp_path):
    (tmp_path / "test_sample.py").write_text(
        "import pytest\n"
        "@pytest.mark.parametrize('value', range(18))\n"
        "def test_case(value):\n    assert value >= 0\n"
        "def test_excluded():\n    raise AssertionError('must be deselected')\n",
        encoding="utf-8",
    )
    expected = [f"test_sample.py::test_case[{i}]" for i in range(18)]
    parts = []
    for shard in range(1, 4):
        result = subprocess.run(
            [
                sys.executable,
                str(LAUNCHER),
                "--shard",
                str(shard),
                "--shards",
                "3",
                "--",
                "--collect-only",
                "-q",
                "--deselect=test_sample.py::test_excluded",
            ],
            cwd=tmp_path,
            capture_output=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        selected = [line for line in result.stdout.splitlines() if line.startswith("test_sample.")]
        assert f"selected {len(selected)}/18 filtered collected nodes" in result.stdout
        assert selected == [node for node in expected if node in selected]
        parts.append(selected)
    assert Counter(node for part in parts for node in part) == Counter(expected)


def test_launcher_preserves_pytest_failure_and_maxfail(tmp_path):
    (tmp_path / "test_sample.py").write_text(
        "from pathlib import Path\n"
        "def test_first():\n    assert False, 'deliberate failure'\n"
        "def test_later():\n    Path('unexpected.txt').write_bytes(b'executed')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(LAUNCHER), "--shard", "1", "--shards", "1", "--", "--maxfail=1", "-q"],
        cwd=tmp_path,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    assert "deliberate failure" in result.stdout
    assert not (tmp_path / "unexpected.txt").exists()
