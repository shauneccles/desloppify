"""Direct tests for Python private-import detector helpers."""

from __future__ import annotations

import desloppify.languages.python.detectors.private_imports as private_imports_mod


def test_resolve_import_target_matches_import_graph_fragments():
    source_file = "src/main.py"
    dep_graph = {
        source_file: {
            "imports": {
                "pkg/internal.py",
                "pkg/public.py",
            }
        }
    }

    matches = private_imports_mod._resolve_import_target(
        source_file,
        "pkg.internal",
        set(dep_graph[source_file]["imports"]),
        dep_graph,
    )
    assert "pkg/internal.py" in matches
    assert "pkg/public.py" not in matches


def test_detect_private_imports_reports_cross_module_private_symbols(tmp_path):
    source = tmp_path / "feature" / "main.py"
    target = tmp_path / "lib" / "private_mod.py"
    source.parent.mkdir(parents=True)
    target.parent.mkdir(parents=True)

    source.write_text("from lib.private_mod import _hidden, visible\n")
    target.write_text("def _hidden():\n    return 1\n")

    dep_graph = {
        str(source): {"imports": {str(target)}},
        str(target): {"imports": set()},
    }

    entries, checked = private_imports_mod.detect_private_imports(dep_graph)
    assert checked == 2
    assert len(entries) == 1
    assert entries[0]["detail"]["symbol"] == "_hidden"
    assert entries[0]["detail"]["target_file"].endswith("private_mod.py")
    assert "Cross-module private import" in entries[0]["summary"]


def test_detect_private_imports_uses_parallel_path_for_large_graph(tmp_path, monkeypatch):
    source = tmp_path / "feature" / "main.py"
    target = tmp_path / "lib" / "private_mod.py"
    source.parent.mkdir(parents=True)
    target.parent.mkdir(parents=True)

    source.write_text("from lib.private_mod import _hidden\n")
    target.write_text("def _hidden():\n    return 1\n")

    dep_graph = {
        str(source): {"imports": {str(target)}},
        str(target): {"imports": set()},
    }

    for index in range(private_imports_mod._PRIVATE_IMPORTS_PARALLEL_MIN_FILES):
        extra = tmp_path / "extra" / f"m_{index}.py"
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("x = 1\n")
        dep_graph[str(extra)] = {"imports": set()}

    called = {"value": False}
    real_parallel = private_imports_mod.process_files_parallel

    def _spy_process_files_parallel(*args, **kwargs):
        called["value"] = True
        return real_parallel(*args, force_parallel=False, **kwargs)

    monkeypatch.setattr(private_imports_mod, "process_files_parallel", _spy_process_files_parallel)

    entries, checked = private_imports_mod.detect_private_imports(dep_graph)

    assert called["value"] is True
    assert checked >= 2
    assert any(e["detail"]["symbol"] == "_hidden" for e in entries)
