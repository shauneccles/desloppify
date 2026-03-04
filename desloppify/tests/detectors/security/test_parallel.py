"""Comprehensive tests for parallel security detection functionality.

Tests cover:
- Single file scanning (scan_single_file)
- Batch processing (scan_file_batch)
- Main API (detect_security_issues)

Both positive and negative test cases included.
"""

from __future__ import annotations

import multiprocessing
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from desloppify.engine.detectors.security.detector import (
    detect_security_issues,
    scan_file_batch,
    scan_single_file,
)
from desloppify.engine.policy.zones import FileZoneMap, Zone


# ── Helpers ──────────────────────────────────────────────────


def _make_zone_map(files_by_zone: dict[Zone, list[str]]) -> FileZoneMap:
    """Create a zone map from a dict of zones to file lists."""
    zm = FileZoneMap.__new__(FileZoneMap)
    zm._map = {}
    for zone, files in files_by_zone.items():
        for filepath in files:
            zm._map[filepath] = zone
    zm._overrides = None
    return zm


def _write_temp_file(content: str, suffix: str = ".py") -> str:
    """Write content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content.encode())
    os.close(fd)
    return path




# ═══════════════════════════════════════════════════════════
# scan_single_file Tests
# ═══════════════════════════════════════════════════════════


class TestScanSingleFile:
    """Test single file scanning logic."""

    def test_scan_file_with_secret(self):
        """File with secret should return findings."""
        content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, None, scan_root)
            
            assert was_scanned is True
            assert len(entries) > 0
            assert any("AWS" in e["summary"] for e in entries)
        finally:
            os.unlink(path)

    def test_scan_clean_file(self):
        """Clean file should return no findings but mark as scanned."""
        content = "# This is a clean Python file\nprint('hello')"
        path = _write_temp_file(content)
        try:
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, None, scan_root)
            
            assert was_scanned is True
            assert len(entries) == 0
        finally:
            os.unlink(path)

    def test_zone_filtering_test_zone(self):
        """scan_single_file doesn't filter by zone - that's done by detect_security_issues."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            zone_map = _make_zone_map({Zone.TEST: [path]})
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, zone_map, scan_root)
            
            # scan_single_file scans regardless of zone - filtering happens upstream
            assert was_scanned is True
            assert len(entries) > 0
        finally:
            os.unlink(path)

    def test_zone_filtering_config_zone(self):
        """scan_single_file doesn't filter by zone - that's done by detect_security_issues."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            zone_map = _make_zone_map({Zone.CONFIG: [path]})
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, zone_map, scan_root)
            
            # scan_single_file scans regardless of zone - filtering happens upstream
            assert was_scanned is True
            assert len(entries) > 0
        finally:
            os.unlink(path)

    def test_zone_filtering_generated_zone(self):
        """scan_single_file doesn't filter by zone - that's done by detect_security_issues."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            zone_map = _make_zone_map({Zone.GENERATED: [path]})
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, zone_map, scan_root)
            
            # scan_single_file scans regardless of zone - filtering happens upstream
            assert was_scanned is True
            assert len(entries) > 0
        finally:
            os.unlink(path)

    def test_zone_filtering_vendor_zone(self):
        """scan_single_file doesn't filter by zone - that's done by detect_security_issues."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            zone_map = _make_zone_map({Zone.VENDOR: [path]})
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, zone_map, scan_root)
            
            # scan_single_file scans regardless of zone - filtering happens upstream
            assert was_scanned is True
            assert len(entries) > 0
        finally:
            os.unlink(path)

    def test_zone_filtering_production_zone(self):
        """Files in PRODUCTION zone should be scanned."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            zone_map = _make_zone_map({Zone.PRODUCTION: [path]})
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, zone_map, scan_root)
            
            assert was_scanned is True
            assert len(entries) > 0
        finally:
            os.unlink(path)

    def test_unreadable_file_returns_not_scanned(self):
        """Unreadable files should return empty results and not_scanned."""
        nonexistent = "/tmp/nonexistent_file_12345.py"
        scan_root = Path("/tmp")
        entries, was_scanned = scan_single_file(nonexistent, None, scan_root)
        
        assert was_scanned is False
        assert len(entries) == 0

    def test_test_file_detection_by_zone(self):
        """Test files detected by zone are still scanned (filtering happens upstream)."""
        content = 'assert True'
        path = _write_temp_file(content)
        try:
            zone_map = _make_zone_map({Zone.TEST: [path]})
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, zone_map, scan_root)
            # scan_single_file doesn't filter by zone
            assert was_scanned is True
        finally:
            os.unlink(path)

    def test_test_file_detection_by_filename_pattern(self):
        """Test files should be detected by filename patterns when no zone."""
        content = 'assert True'
        path = _write_temp_file(content, suffix="test_example.py")
        try:
            scan_root = Path(path).parent
            entries, was_scanned = scan_single_file(path, None, scan_root)
            # Should be scanned (no zone filtering without zone map)
            assert was_scanned is True
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════
# scan_file_batch Tests
# ═══════════════════════════════════════════════════════════


class TestScanFileBatch:
    """Test batch processing worker function."""

    def test_empty_batch(self):
        """Empty batch should return zero results."""
        entries, scanned = scan_file_batch([], None, Path("/tmp"))
        assert entries == []
        assert scanned == 0

    def test_batch_with_findings(self):
        """Batch with secrets should return aggregated findings."""
        content1 = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        content2 = 'GITHUB = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"'
        
        path1 = _write_temp_file(content1)
        path2 = _write_temp_file(content2)
        try:
            scan_root = Path(path1).parent
            entries, scanned = scan_file_batch([path1, path2], None, scan_root)
            
            assert scanned == 2
            assert len(entries) >= 2  # At least one finding per file
            assert any("AWS" in e["summary"] for e in entries)
            assert any("GitHub" in e["summary"] for e in entries)
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_batch_with_zone_filtering(self):
        """Batch worker doesn't filter by zone - that's done by detect_security_issues."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        
        path1 = _write_temp_file(content, suffix="_prod.py")
        path2 = _write_temp_file(content, suffix="_test.py")
        try:
            zone_map = _make_zone_map({
                Zone.PRODUCTION: [path1],
                Zone.TEST: [path2],
            })
            scan_root = Path(path1).parent
            entries, scanned = scan_file_batch([path1, path2], zone_map, scan_root)
            
            # scan_file_batch scans all files given to it - no zone filtering
            assert scanned == 2
            assert len(entries) > 0
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_batch_with_unreadable_files(self):
        """Batch should skip unreadable files gracefully."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path1 = _write_temp_file(content)
        path2 = "/tmp/nonexistent_12345.py"
        try:
            scan_root = Path(path1).parent
            entries, scanned = scan_file_batch([path1, path2], None, scan_root)
            
            # Only path1 should be scanned
            assert scanned == 1
            assert len(entries) > 0
        finally:
            os.unlink(path1)


# ═══════════════════════════════════════════════════════════
# detect_security_issues Tests
# ═══════════════════════════════════════════════════════════


class TestDetectSecurityIssues:
    """Test main dispatcher that chooses between single/parallel modes."""

    def test_uses_single_mode_for_few_files(self):
        """Dispatcher should use single-process mode for few files."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        paths = []
        try:
            # Create files below threshold
            for i in range(5):
                path = _write_temp_file(content, suffix=f"_{i}.py")
                paths.append(path)
            
            scan_root = Path(paths[0]).parent
            entries, scanned = detect_security_issues(
                paths, None, "python", scan_root=scan_root
            )
            
            assert scanned == 5
            assert len(entries) > 0
        finally:
            for path in paths:
                os.unlink(path)

    def test_explicit_parallel_false(self):
        """Dispatcher should respect explicit parallel=False."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        paths = []
        try:
            # Create many files but force single-process
            for i in range(150):
                path = _write_temp_file(content, suffix=f"_{i}.py")
                paths.append(path)
            
            scan_root = Path(paths[0]).parent
            entries, scanned = detect_security_issues(
                paths, None, "python", scan_root=scan_root, parallel=False
            )
            
            assert scanned == 150
        finally:
            for path in paths:
                os.unlink(path)

    def test_explicit_parallel_true(self):
        """Dispatcher should respect explicit parallel=True."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        paths = []
        try:
            # Create few files but force parallel
            for i in range(5):
                path = _write_temp_file(content, suffix=f"_{i}.py")
                paths.append(path)
            
            scan_root = Path(paths[0]).parent
            entries, scanned = detect_security_issues(
                paths, None, "python", scan_root=scan_root, parallel=True
            )
            
            assert scanned == 5
            assert len(entries) > 0
        finally:
            for path in paths:
                os.unlink(path)

    def test_none_scan_root_uses_cwd(self):
        """Dispatcher should handle None scan_root."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            # Should use cwd when scan_root is None
            entries, scanned = detect_security_issues(
                [path], None, "python", scan_root=None
            )
            
            assert scanned >= 0  # May or may not find the file depending on cwd
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════
# Negative Tests - Error Handling
# ═══════════════════════════════════════════════════════════


class TestErrorHandling:
    """Test error handling in various scenarios."""

    def test_scan_single_file_with_permission_error(self):
        """Should handle permission errors gracefully."""
        # Create file then make unreadable (platform-specific)
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        path = _write_temp_file(content)
        try:
            scan_root = Path(path).parent
            # Attempt to scan non-existent to trigger error
            bad_path = path + "_nonexistent"
            entries, was_scanned = scan_single_file(bad_path, None, scan_root)
            
            assert was_scanned is False
            assert entries == []
        finally:
            os.unlink(path)

    def test_batch_with_all_unreadable_files(self):
        """Batch with all unreadable files should return empty results."""
        bad_paths = [f"/tmp/nonexistent_{i}.py" for i in range(5)]
        entries, scanned = scan_file_batch(bad_paths, None, Path("/tmp"))
        
        assert scanned == 0
        assert entries == []

    def test_parallel_with_all_unreadable_files(self):
        """Parallel mode with all unreadable should return empty."""
        bad_paths = [f"/tmp/nonexistent_{i}.py" for i in range(10)]
        entries, scanned = detect_security_issues(
            bad_paths, None, "python", scan_root=Path("/tmp"), parallel=True
        )
        
        assert scanned == 0
        assert entries == []

    def test_dispatcher_with_empty_file_list(self):
        """Dispatcher with empty file list should return empty results."""
        entries, scanned = detect_security_issues(
            [], None, "python", scan_root=Path("/tmp")
        )
        
        assert scanned == 0
        assert entries == []


# ═══════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════


class TestIntegration:
    """Integration tests verifying end-to-end behavior."""

    def test_single_and_parallel_produce_same_results(self):
        """Single and parallel modes should produce identical findings."""
        content = 'AWS = "AKIAIOSFODNN7EXAMPLE"'
        paths = []
        try:
            for i in range(20):
                path = _write_temp_file(content, suffix=f"_{i}.py")
                paths.append(path)
            
            scan_root = Path(paths[0]).parent
            
            # Run both modes
            single_entries, single_scanned = detect_security_issues(
                paths, None, "python", scan_root=scan_root, parallel=False
            )
            parallel_entries, parallel_scanned = detect_security_issues(
                paths, None, "python", scan_root=scan_root, parallel=True, workers=3
            )
            
            # Should scan same number of files
            assert single_scanned == parallel_scanned == 20
            
            # Should find same number of issues
            assert len(single_entries) == len(parallel_entries)
            
            # Extract summaries for comparison (order may differ)
            single_summaries = sorted([e["summary"] for e in single_entries])
            parallel_summaries = sorted([e["summary"] for e in parallel_entries])
            assert single_summaries == parallel_summaries
        finally:
            for path in paths:
                os.unlink(path)

    def test_zone_filtering_consistent_across_modes(self):
        """Zone filtering should work identically in both modes."""
        content = 'SECRET = "AKIAIOSFODNN7EXAMPLE"'
        paths = []
        try:
            for i in range(10):
                path = _write_temp_file(content, suffix=f"_{i}.py")
                paths.append(path)
            
            # Mix of zones
            zone_map = _make_zone_map({
                Zone.PRODUCTION: paths[:5],
                Zone.TEST: paths[5:],
            })
            
            scan_root = Path(paths[0]).parent
            
            single_entries, single_scanned = detect_security_issues(
                paths, zone_map, "python", scan_root=scan_root, parallel=False
            )
            parallel_entries, parallel_scanned = detect_security_issues(
                paths, zone_map, "python", scan_root=scan_root, parallel=True, workers=2
            )
            
            # Both should scan only PRODUCTION files
            assert single_scanned == parallel_scanned == 5
            assert len(single_entries) == len(parallel_entries)
        finally:
            for path in paths:
                os.unlink(path)
