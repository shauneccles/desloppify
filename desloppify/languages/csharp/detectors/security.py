"""C#-specific security detectors."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from desloppify.engine.detectors.security import rules as security_detector_mod
from desloppify.engine.policy.zones import FileZoneMap, Zone
from desloppify.engine.parallel_utils import process_files_parallel

logger = logging.getLogger(__name__)

_SQL_INTERPOLATION_RE = re.compile(
    r"\b(?:SqlCommand|Execute(?:Reader|NonQuery|Scalar)?)\s*\([^)]*\$\"",
    re.IGNORECASE,
)
_SQL_CONCAT_RE = re.compile(
    r"\b(?:SqlCommand|Execute(?:Reader|NonQuery|Scalar)?)\s*\([^)]*(?:\+|string\.Format)",
    re.IGNORECASE,
)
_RNG_IN_SECURITY_CONTEXT_RE = re.compile(
    r"\bnew\s+Random\s*\(\s*\).*(?:token|password|secret|key|nonce|salt|otp)",
    re.IGNORECASE,
)
_DISABLED_TLS_VERIFY_RE = re.compile(
    r"ServerCertificateValidationCallback\s*\+=\s*\([^)]*\)\s*=>\s*true",
    re.IGNORECASE,
)
_BINARY_FORMATTER_RE = re.compile(
    r"\bBinaryFormatter\b|\bSoapFormatter\b",
    re.IGNORECASE,
)


# ── Parallel Processing Support ─────────────────────────────────────────────


def _process_csharp_security_file(filepath: str, zone_map: FileZoneMap | None) -> list[dict]:
    """Process a single C# file for security issues."""
    if not filepath.endswith(".cs"):
        return []
    
    if zone_map is not None:
        zone = zone_map.get(filepath)
        if zone in (Zone.GENERATED, Zone.VENDOR):
            return []

    try:
        content = Path(filepath).read_text(errors="replace")
    except OSError as exc:
        logger.debug(
            "Skipping unreadable C# file %s in security detector: %s", filepath, exc
        )
        return []

    entries: list[dict] = []
    lines = content.splitlines()
    
    for line_num, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue

        if _SQL_INTERPOLATION_RE.search(line) or _SQL_CONCAT_RE.search(line):
            entries.append(
                security_detector_mod.make_security_entry(
                    filepath,
                    line_num,
                    line,
                    security_detector_mod.SecurityRule(
                        check_id="sql_injection",
                        summary="Potential SQL injection: dynamic SQL command construction",
                        severity="critical",
                        confidence="high",
                        remediation="Use parameterized SQL commands with SqlParameter.",
                    ),
                )
            )

        if _RNG_IN_SECURITY_CONTEXT_RE.search(line):
            entries.append(
                security_detector_mod.make_security_entry(
                    filepath,
                    line_num,
                    line,
                    security_detector_mod.SecurityRule(
                        check_id="insecure_random",
                        summary="Insecure random in security-sensitive context",
                        severity="medium",
                        confidence="medium",
                        remediation="Use RandomNumberGenerator.GetBytes or a cryptographic RNG.",
                    ),
                )
            )

        if _DISABLED_TLS_VERIFY_RE.search(line):
            entries.append(
                security_detector_mod.make_security_entry(
                    filepath,
                    line_num,
                    line,
                    security_detector_mod.SecurityRule(
                        check_id="weak_crypto_tls",
                        summary="TLS certificate validation disabled",
                        severity="high",
                        confidence="high",
                        remediation="Remove custom callback or validate certificates properly.",
                    ),
                )
            )

        if _BINARY_FORMATTER_RE.search(line):
            entries.append(
                security_detector_mod.make_security_entry(
                    filepath,
                    line_num,
                    line,
                    security_detector_mod.SecurityRule(
                        check_id="unsafe_deserialization",
                        summary="Unsafe formatter usage may enable insecure deserialization",
                        severity="high",
                        confidence="medium",
                        remediation="Use safe serializers (System.Text.Json) instead of BinaryFormatter/SoapFormatter.",
                    ),
                )
            )

    return entries


def _csharp_security_batch_worker(files: list[str], zone_map: FileZoneMap | None) -> list[dict]:
    """Worker function to process a batch of C# files for security issues."""
    results = []
    for filepath in files:
        results.extend(_process_csharp_security_file(filepath, zone_map))
    return results


def detect_csharp_security(
    files: list[str],
    zone_map: FileZoneMap | None,
) -> tuple[list[dict], int]:
    """Detect C#-specific security issues. Returns (entries, files_scanned)."""
    cs_files = [f for f in files if f.endswith(".cs")]
    if zone_map is not None:
        cs_files = [
            f
            for f in cs_files
            if zone_map.get(f) not in (Zone.GENERATED, Zone.VENDOR)
        ]
    scanned = len(cs_files)
    
    # Use parallel processing for CPU-intensive line-by-line regex matching
    entries = process_files_parallel(
        files=cs_files,
        worker_func=_csharp_security_batch_worker,
        mode="extend",
        min_files=50,
        task_name="C# security detection",
        zone_map=zone_map,
    )

    return entries, scanned
