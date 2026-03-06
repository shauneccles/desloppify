"""Runtime helpers for review batch execution."""

from __future__ import annotations

import orjson

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runner_parallel import BatchProgressEvent


@dataclass(frozen=True)
class BatchRunSummaryConfig:
    """Inputs required to write the run_summary.json payload."""

    created_at: str
    run_stamp: str
    runner: str
    run_parallel: bool
    selected_indexes: list[int]
    allow_partial: bool
    max_parallel_batches: int
    batch_timeout_seconds: int
    batch_max_retries: int
    batch_retry_backoff_seconds: float
    heartbeat_seconds: float
    stall_warning_seconds: int
    stall_kill_seconds: int
    immutable_packet_path: Path
    prompt_packet_path: Path
    run_dir: Path
    logs_dir: Path
    run_log_path: Path
    backlog_gate: dict[str, object] | None = None


@dataclass
class BatchProgressTracker:
    """Tracks per-batch lifecycle state and emits progress/log events."""

    selected_indexes: list[int]
    prompt_files: dict[int, Path]
    output_files: dict[int, Path]
    log_files: dict[int, Path]
    total_batches: int
    colorize_fn: Callable[[str, str], str]
    append_run_log_fn: Callable[[str], None]
    stall_warning_seconds: int
    batch_positions: dict[int, int] = field(init=False)
    batch_status: dict[str, dict[str, object]] = field(init=False)
    stall_warned_batches: set[int] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        self.batch_positions = {
            batch_idx: pos + 1 for pos, batch_idx in enumerate(self.selected_indexes)
        }
        self.batch_status = {
            str(idx + 1): {
                "position": self.batch_positions.get(idx, 0),
                "status": "pending",
                "prompt_path": str(self.prompt_files[idx]),
                "result_path": str(self.output_files[idx]),
                "log_path": str(self.log_files[idx]),
            }
            for idx in self.selected_indexes
        }

    def report(self, batch_index: int, event: str, code: int | None = None, **details) -> None:
        if event == "heartbeat":
            self._report_heartbeat(details)
            return

        position = self.batch_positions.get(batch_index, 0)
        key = str(batch_index + 1)
        state = self.batch_status.setdefault(
            key,
            {
                "position": position,
                "status": "pending",
                "prompt_path": str(self.prompt_files.get(batch_index, "")),
                "result_path": str(self.output_files.get(batch_index, "")),
                "log_path": str(self.log_files.get(batch_index, "")),
            },
        )
        if event == "queued":
            state["status"] = "queued"
            print(
                self.colorize_fn(
                    f"  Batch {position}/{self.total_batches} queued (#{batch_index + 1})",
                    "dim",
                )
            )
            self.append_run_log_fn(
                f"batch-queued batch={batch_index + 1} position={position}/{self.total_batches}"
            )
            return
        if event == "start":
            state["status"] = "running"
            state["started_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            print(
                self.colorize_fn(
                    f"  Batch {position}/{self.total_batches} started (#{batch_index + 1})",
                    "dim",
                )
            )
            self.append_run_log_fn(
                f"batch-start batch={batch_index + 1} position={position}/{self.total_batches}"
            )
            return
        if event != "done":
            return
        self._mark_done(batch_index, code=code, details=details)

    def report_event(self, progress_event: BatchProgressEvent) -> None:
        """Typed event entrypoint shared with runner_parallel callbacks."""
        if not hasattr(progress_event, "batch_index") or not hasattr(
            progress_event,
            "event",
        ):
            return
        details = getattr(progress_event, "details", {})
        payload = details if isinstance(details, dict) else {}
        self.report(
            int(getattr(progress_event, "batch_index", -1)),
            str(getattr(progress_event, "event", "")),
            getattr(progress_event, "code", None),
            **payload,
        )

    def record_execution_issue(self, batch_index: int, exc: Exception) -> None:
        if batch_index < 0:
            self.append_run_log_fn(f"execution-error heartbeat error={exc}")
            return
        self.append_run_log_fn(f"execution-error batch={batch_index + 1} error={exc}")

    def mark_interrupted(self) -> None:
        for idx in self.selected_indexes:
            key = str(idx + 1)
            state = self.batch_status.setdefault(
                key,
                {"position": self.batch_positions.get(idx, 0), "status": "pending"},
            )
            if state.get("status") in {"pending", "queued", "running"}:
                state["status"] = "interrupted"

    def mark_final_statuses(
        self,
        *,
        selected_indexes: list[int],
        failure_set: set[int],
        execution_failure_set: set[int],
    ) -> None:
        for idx in selected_indexes:
            key = str(idx + 1)
            state = self.batch_status.setdefault(
                key,
                {"position": self.batch_positions.get(idx, 0), "status": "pending"},
            )
            if idx not in failure_set:
                state["status"] = "succeeded"
                continue
            if idx in execution_failure_set:
                state["status"] = "failed"
                continue
            if not self.output_files[idx].exists():
                state["status"] = "missing_output"
                continue
            state["status"] = "parse_failed"

    def _report_heartbeat(self, details: dict[str, object]) -> None:
        active, queued, elapsed = _normalize_heartbeat_payload(details)
        if not active and not queued:
            return
        segments = _heartbeat_segments(active, elapsed)
        queued_segment = f", queued {len(queued)}" if queued else ""
        print(
            self.colorize_fn(
                "  Batch heartbeat: "
                f"{len(active)}/{self.total_batches} active{queued_segment} "
                f"({', '.join(segments) if segments else 'running batches pending'})",
                "dim",
            )
        )
        self.append_run_log_fn(
            "heartbeat "
            f"active={[idx + 1 for idx in active]} queued={[idx + 1 for idx in queued]} "
            f"elapsed={{{_heartbeat_elapsed_log(active, elapsed)}}}"
        )
        if self.stall_warning_seconds <= 0:
            return
        slow_active = _slow_active_batches(
            active,
            elapsed=elapsed,
            threshold=self.stall_warning_seconds,
        )
        newly_warned = [idx for idx in slow_active if idx not in self.stall_warned_batches]
        if not newly_warned:
            return
        self.stall_warned_batches.update(newly_warned)
        warning_message = (
            "  Stall warning: batches "
            f"{[idx + 1 for idx in sorted(newly_warned)]} exceeded "
            f"{self.stall_warning_seconds}s elapsed. "
            "This may be normal for long runs; review run.log and batch logs."
        )
        print(self.colorize_fn(warning_message, "yellow"))
        self.append_run_log_fn(
            "stall-warning "
            f"threshold={self.stall_warning_seconds}s "
            f"batches={[idx + 1 for idx in sorted(newly_warned)]}"
        )

    def _mark_done(self, batch_index: int, *, code: int | None, details: dict[str, object]) -> None:
        position = self.batch_positions.get(batch_index, 0)
        key = str(batch_index + 1)
        state = self.batch_status.setdefault(
            key,
            {
                "position": position,
                "status": "pending",
                "prompt_path": str(self.prompt_files.get(batch_index, "")),
                "result_path": str(self.output_files.get(batch_index, "")),
                "log_path": str(self.log_files.get(batch_index, "")),
            },
        )
        status = "done" if code == 0 else f"failed ({code})"
        tone = "dim" if code == 0 else "yellow"
        elapsed_seconds = details.get("elapsed_seconds")
        elapsed_suffix = ""
        if isinstance(elapsed_seconds, int | float):
            elapsed_suffix = f" in {int(max(0, elapsed_seconds))}s"
            state["elapsed_seconds"] = int(max(0, elapsed_seconds))
        state["status"] = "succeeded" if code == 0 else "failed"
        state["exit_code"] = int(code) if isinstance(code, int) else code
        state["completed_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        self.stall_warned_batches.discard(batch_index)
        print(
            self.colorize_fn(
                f"  Batch {position}/{self.total_batches} {status}{elapsed_suffix} (#{batch_index + 1})",
                tone,
            )
        )
        self.append_run_log_fn(
            f"batch-done batch={batch_index + 1} position={position}/{self.total_batches} "
            f"code={code} elapsed={state.get('elapsed_seconds', 0)}"
        )


def _normalize_heartbeat_payload(
    details: dict[str, object],
) -> tuple[list[int], list[int], dict[int, object]]:
    active = details.get("active_batches")
    queued = details.get("queued_batches", [])
    elapsed = details.get("elapsed_seconds", {})
    active_list = active if isinstance(active, list) else []
    queued_list = queued if isinstance(queued, list) else []
    elapsed_map = elapsed if isinstance(elapsed, dict) else {}
    return active_list, queued_list, elapsed_map


def _elapsed_seconds_for(elapsed: dict[int, object], index: int) -> int:
    raw_secs = elapsed.get(index, 0)
    return int(raw_secs) if isinstance(raw_secs, int | float) else 0


def _heartbeat_segments(active: list[int], elapsed: dict[int, object]) -> list[str]:
    segments: list[str] = []
    for idx in active[:6]:
        segments.append(f"#{idx + 1}:{_elapsed_seconds_for(elapsed, idx)}s")
    if len(active) > 6:
        segments.append(f"+{len(active) - 6} more")
    return segments


def _heartbeat_elapsed_log(active: list[int], elapsed: dict[int, object]) -> str:
    return ", ".join(f"{idx + 1}:{elapsed.get(idx, 0)}" for idx in active)


def _slow_active_batches(
    active: list[int],
    *,
    elapsed: dict[int, object],
    threshold: int,
) -> list[int]:
    return [
        idx
        for idx in active
        if _elapsed_seconds_for(elapsed, idx) >= threshold
    ]


def resolve_run_log_path(
    raw_run_log_file: object,
    *,
    project_root: Path,
    run_dir: Path,
) -> Path:
    if isinstance(raw_run_log_file, str) and raw_run_log_file.strip():
        candidate = Path(raw_run_log_file.strip()).expanduser()
        run_log_path = candidate if candidate.is_absolute() else project_root / candidate
    else:
        run_log_path = run_dir / "run.log"
    run_log_path.parent.mkdir(parents=True, exist_ok=True)
    return run_log_path


def make_run_log_writer(run_log_path: Path) -> Callable[[str], None]:
    def _append_run_log(message: str) -> None:
        line = f"{datetime.now(UTC).isoformat(timespec='seconds')} {message}\n"
        try:
            with run_log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            return

    return _append_run_log


def build_batch_tasks(
    *,
    selected_indexes: list[int],
    prompt_files: dict[int, Path],
    output_files: dict[int, Path],
    log_files: dict[int, Path],
    project_root: Path,
    run_codex_batch_fn: Callable[..., int],
) -> dict[int, Callable[[], int]]:
    return {
        idx: partial(
            _run_batch_task,
            batch_index=idx,
            prompt_path=prompt_files[idx],
            output_path=output_files[idx],
            log_path=log_files[idx],
            project_root=project_root,
            run_codex_batch_fn=run_codex_batch_fn,
        )
        for idx in selected_indexes
    }


def write_run_summary(
    *,
    summary_path: Path,
    summary_config: BatchRunSummaryConfig,
    batch_status: dict[str, dict[str, object]],
    successful_batches: list[int],
    failed_batches: list[int],
    safe_write_text_fn: Callable[[Path, str], None],
    colorize_fn: Callable[[str, str], str],
    append_run_log_fn: Callable[[str], None],
    interrupted: bool = False,
    interruption_reason: str | None = None,
) -> None:
    run_summary: dict[str, object] = {
        "created_at": summary_config.created_at,
        "run_stamp": summary_config.run_stamp,
        "runner": summary_config.runner,
        "parallel": summary_config.run_parallel,
        "selected_batches": [idx + 1 for idx in summary_config.selected_indexes],
        "successful_batches": successful_batches,
        "failed_batches": failed_batches,
        "allow_partial": summary_config.allow_partial,
        "max_parallel_batches": (
            summary_config.max_parallel_batches if summary_config.run_parallel else 1
        ),
        "batch_timeout_seconds": summary_config.batch_timeout_seconds,
        "batch_max_retries": summary_config.batch_max_retries,
        "batch_retry_backoff_seconds": summary_config.batch_retry_backoff_seconds,
        "batch_heartbeat_seconds": (
            summary_config.heartbeat_seconds if summary_config.run_parallel else None
        ),
        "batch_stall_warning_seconds": (
            summary_config.stall_warning_seconds if summary_config.run_parallel else None
        ),
        "batch_stall_kill_seconds": summary_config.stall_kill_seconds,
        "immutable_packet": str(summary_config.immutable_packet_path),
        "blind_packet": str(summary_config.prompt_packet_path),
        "run_dir": str(summary_config.run_dir),
        "logs_dir": str(summary_config.logs_dir),
        "run_log": str(summary_config.run_log_path),
        "batches": batch_status,
    }
    if isinstance(summary_config.backlog_gate, dict):
        run_summary["backlog_gate"] = summary_config.backlog_gate
    if interrupted:
        run_summary["interrupted"] = True
        if interruption_reason:
            run_summary["interruption_reason"] = interruption_reason
    safe_write_text_fn(
        summary_path,
        orjson.dumps(run_summary, option=orjson.OPT_INDENT_2).decode("utf-8") + "\n",
    )
    print(colorize_fn(f"  Run summary: {summary_path}", "dim"))
    append_run_log_fn(f"run-summary {summary_path}")


def _run_batch_task(
    *,
    batch_index: int,
    prompt_path: Path,
    output_path: Path,
    log_path: Path,
    project_root: Path,
    run_codex_batch_fn: Callable[..., int],
) -> int:
    try:
        prompt = prompt_path.read_text()
    except OSError as exc:
        raise RuntimeError(
            f"unable to read prompt for batch #{batch_index + 1}: {prompt_path}"
        ) from exc
    return run_codex_batch_fn(
        prompt=prompt,
        repo_root=project_root,
        output_file=output_path,
        log_file=log_path,
    )


__all__ = [
    "BatchProgressTracker",
    "BatchRunSummaryConfig",
    "build_batch_tasks",
    "make_run_log_writer",
    "resolve_run_log_path",
    "write_run_summary",
]
