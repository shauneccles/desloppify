"""Python language security + coverage wiring helpers."""

from __future__ import annotations

import shutil

from desloppify.base.discovery.source import collect_exclude_dirs
from desloppify.languages._framework.base.types import DetectorCoverageStatus, LangSecurityResult
from desloppify.languages.python.detectors.bandit_adapter import detect_with_bandit
from desloppify.languages.python._helpers import scan_root_from_files


def missing_bandit_coverage() -> DetectorCoverageStatus:
    return DetectorCoverageStatus(
        detector="security",
        status="reduced",
        confidence=0.6,
        summary="bandit is not installed — Python-specific security checks will be skipped.",
        impact=(
            "Python-specific security coverage is reduced; clean security output may "
            "miss shell injection, unsafe deserialization, and risky SQL/subprocess patterns."
        ),
        remediation="Install Bandit: pip install bandit",
        tool="bandit",
        reason="missing_dependency",
    )


def python_scan_coverage_prerequisites() -> list[DetectorCoverageStatus]:
    if shutil.which("bandit") is not None:
        return []
    return [missing_bandit_coverage()]


def detect_python_security(files, zone_map) -> LangSecurityResult:
    if not files:
        return LangSecurityResult(entries=[], files_scanned=0)

    scan_root = scan_root_from_files(files)
    if scan_root is None:
        return LangSecurityResult(entries=[], files_scanned=0)

    exclude_dirs = collect_exclude_dirs(scan_root)

    result = detect_with_bandit(
        path=scan_root,
        files=list(files),
        zone_map=zone_map,
        exclude_dirs=exclude_dirs,
    )
    coverage = result.status.coverage()
    return LangSecurityResult(
        entries=result.entries,
        files_scanned=result.files_scanned,
        coverage=coverage,
    )


__all__ = [
    "detect_python_security",
    "missing_bandit_coverage",
    "python_scan_coverage_prerequisites",
]
