"""Tests for Python Bandit adapter zone filtering behavior."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from desloppify.base.discovery.paths import get_project_root
from desloppify.engine.policy.zones import Zone
from desloppify.languages.python.detectors import bandit_adapter as adapter_mod


@dataclass
class _StubZoneMap:
    zone: Zone

    def get(self, _path: str) -> Zone:
        return self.zone


class _RelOnlyZoneMap:
    def get(self, path: str) -> Zone:
        return Zone.TEST if path.startswith("desloppify/tests/") else Zone.PRODUCTION


def _sample_result(*, test_id: str = "B108") -> dict[str, object]:
    return {
        "filename": "desloppify/tests/test_file.py",
        "test_id": test_id,
        "issue_severity": "MEDIUM",
        "issue_confidence": "MEDIUM",
        "line_number": 10,
        "issue_text": "hardcoded temp path",
        "test_name": "hardcoded_tmp_directory",
        "code": "x = '/tmp/demo'",
        "more_info": "https://example.test",
    }


def test_to_security_entry_skips_test_zone():
    entry = adapter_mod._to_security_entry(_sample_result(), _StubZoneMap(Zone.TEST))
    assert entry is None


def test_to_security_entry_skips_config_zone():
    entry = adapter_mod._to_security_entry(_sample_result(), _StubZoneMap(Zone.CONFIG))
    assert entry is None


def test_to_security_entry_keeps_production_zone():
    entry = adapter_mod._to_security_entry(
        _sample_result(),
        _StubZoneMap(Zone.PRODUCTION),
    )
    assert isinstance(entry, dict)
    assert entry["name"] == "security::B108::desloppify/tests/test_file.py::10"


def test_to_security_entry_normalizes_absolute_paths_before_zone_lookup():
    result = _sample_result()
    result["filename"] = str(get_project_root() / "desloppify/tests/test_file.py")
    entry = adapter_mod._to_security_entry(result, _RelOnlyZoneMap())
    assert entry is None


def test_detect_with_bandit_uses_absolute_scan_path(monkeypatch):
    captured: dict[str, object] = {}

    class _FakeCompleted:
        stdout = '{"results": [], "metrics": {}}'

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _FakeCompleted()

    monkeypatch.setattr(adapter_mod.subprocess, "run", _fake_run)

    result = adapter_mod.detect_with_bandit(
        Path("."),
        zone_map=None,
        exclude_dirs=["/tmp/demo/.venv"],
    )

    assert result.status.state == "ok"
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert Path(cmd[-1]).is_absolute()


def test_detect_with_bandit_files_parallel_uses_framework(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_parallel(*, files, worker_func, **kwargs):
        captured["files"] = files
        captured["worker_func"] = worker_func
        captured["kwargs"] = kwargs
        return [
            {
                "entries": [{"name": "security::B001::x.py::1"}],
                "files_scanned": 2,
                "status": "ok",
                "detail": "",
            }
        ]

    monkeypatch.setattr(adapter_mod, "process_files_parallel", _fake_parallel)

    result = adapter_mod.detect_with_bandit(
        files=["a.py", "b.py"],
        zone_map=None,
        parallel=True,
    )

    assert captured["files"] == ["a.py", "b.py"]
    assert result.status.state == "ok"
    assert result.files_scanned == 2
    assert len(result.entries) == 1


def test_detect_with_bandit_files_parallel_incomplete_returns_error(monkeypatch):
    monkeypatch.setattr(adapter_mod, "process_files_parallel", lambda **_: [])

    result = adapter_mod.detect_with_bandit(
        files=["a.py"],
        zone_map=None,
        parallel=True,
    )

    assert result.status.state == "error"
    assert result.entries == []
