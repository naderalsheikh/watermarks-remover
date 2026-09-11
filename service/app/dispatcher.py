"""Background execution of the database jobs queue with shared leases.

Threads provide local execution capacity; job_queue reserves global capacity
and fences every attempt in the database. Private attempt outputs become
available only through atomic terminal publication in job_lifecycle.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import or_
from sqlalchemy.orm import Session

from .config import Config
from .job_lifecycle import complete_batch, finalize_job, finish_release
from .job_queue import (
    Heartbeat,
    LostLease,
    claim_job,
    configure_queue,
    record_execution,
    recover_expired,
)
from .models import Batch, Job
from .runner import RunnerResult, job_root, run_job

log = logging.getLogger("counselclear")

# Bounded retry for the per-child terminal finalizer below (audit append +
# Release sync). Seconds at most, not minutes: this runs on the dispatcher's
# own worker threads, which occupy the bounded-concurrency pool slots, so an
# exponential schedule that reached minutes would hold a slot (and delay the
# batch's remaining children) for longer than any in-process transient is
# worth. Persistent failures leave a durable receipt for later recovery.
_FINALIZE_ATTEMPTS = 3
_FINALIZE_BACKOFF_S = 0.2


def sync_release(s: Session, job: Job) -> None:
    finish_release(s, job)


class BatchDispatcher:
    """Poll single jobs and batch children without holding transactions during execution."""

    def __init__(
        self,
        *,
        cfg: Config,
        session_factory,
        storage,
        max_concurrent: int,
        no_decision_marker: str,
        poll_interval_s: float = 0.5,
    ) -> None:
        self._cfg = cfg
        self._max_concurrent = max_concurrent
        with session_factory() as s:
            configure_queue(s, max_concurrent)
        self._session_factory = session_factory
        self._storage = storage
        self._no_decision_marker = no_decision_marker
        self._poll_interval_s = poll_interval_s
        self._executor = ThreadPoolExecutor(
            max_workers=max_concurrent, thread_name_prefix="batch-worker"
        )
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="batch-dispatcher")
        self._started = False

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self._started:
                return
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=2)
        self._executor.shutdown(wait=False, cancel_futures=False)

    def wake(self) -> None:
        """Call right after a batch is created so its children dispatch
        promptly instead of waiting up to ``poll_interval_s``."""
        self.start()
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception:
                # A transient DB hiccup must not kill the loop -- the next
                # tick tries again. Queued rows are durable; nothing is lost.
                log.exception("batch dispatcher poll failed")
            self._wake.wait(self._poll_interval_s)
            self._wake.clear()

    def _poll_once(self) -> None:
        with self._lock:
            exclude = set(self._in_flight)
        with self._session_factory() as s:
            recover_expired(s, max_attempts=self._cfg.job_max_attempts)
            q = s.query(Job.id).filter(
                Job.status == "queued", or_(Job.batch_id.isnot(None), Job.requested_by.isnot(None))
            )
            if exclude:
                q = q.filter(~Job.id.in_(exclude))
            job_ids = [
                row[0]
                for row in q.order_by(Job.created_utc, Job.id)
                .limit(max(0, self._max_concurrent - len(exclude)))
                .all()
            ]
        for job_id in job_ids:
            with self._lock:
                if job_id in self._in_flight:
                    continue
                self._in_flight.add(job_id)
            self._executor.submit(self._run_one, job_id)
        self._complete_ready_batches()

    def _complete_ready_batches(self) -> None:
        """Reconcile any unfinished batch whose children are already terminal.

        The normal path marks a batch complete when each child exits
        _run_one_inner, but completion must not depend on that one finalizer
        call succeeding: audit/release-sync errors, process death, or a test
        interruption after a child reaches a terminal status should not leave
        polling clients waiting forever once all children are terminal.
        """
        with self._session_factory() as s:
            batch_ids = [
                row[0] for row in s.query(Batch.id).filter(Batch.finished_utc.is_(None)).all()
            ]
            for batch_id in batch_ids:
                self.check_batch_completion(s, batch_id)

    def _run_one(self, job_id: str) -> None:
        try:
            self._run_one_inner(job_id)
        finally:
            with self._lock:
                self._in_flight.discard(job_id)

    def _run_one_inner(self, job_id: str) -> None:
        with self._session_factory() as s:
            claim = claim_job(s, job_id, self._cfg.job_lease_s)
            if claim is None:
                return
            job = s.get(Job, job_id)
            kind, batch_id = job.kind, job.batch_id
            batch = s.get(Batch, batch_id) if batch_id else None
            actor = job.requested_by or (batch.requested_by if batch else "job-dispatcher")
            receipt = job.execution_receipt
            allowed_root = job_root(self._cfg, job.matter_id, job.id) / "attempts"

        with (
            Heartbeat(self._session_factory, claim, self._cfg.job_lease_s),
            self._session_factory() as execution,
        ):
            execution.info["job_claim"] = claim
            try:
                if receipt is None:
                    res = run_job(self._cfg, execution, job_id, kind=kind, storage=self._storage)
                else:
                    output = Path(receipt["output_dir"]) if receipt.get("output_dir") else None
                    if output is not None:
                        output.resolve().relative_to(allowed_root.resolve())
                    res = RunnerResult(
                        receipt["rc"], receipt["stderr_tail"], receipt["timed_out"], output
                    )
            except LostLease:
                return
            except Exception as exc:
                log.exception("worker invocation failed for %s", job_id)
                execution.rollback()
                res = RunnerResult(
                    rc=-1,
                    timed_out=False,
                    stderr_tail=f"internal dispatcher error: {type(exc).__name__}: {exc}"[:1000],
                )
            for attempt in range(_FINALIZE_ATTEMPTS):
                try:
                    execution.rollback()
                    record_execution(execution, claim, res)
                    finalize_job(
                        execution,
                        job_id,
                        res,
                        actor_id=actor,
                        no_decision_marker=self._no_decision_marker,
                        claim=claim,
                    )
                    return
                except LostLease:
                    return
                except Exception:
                    log.exception("atomic job finalization failed for %s", job_id)
                    if attempt + 1 < _FINALIZE_ATTEMPTS:
                        time.sleep(_FINALIZE_BACKOFF_S * (2**attempt))
            # The persisted receipt and expiring lease let another poll
            # retry publication after outages, without publishing early.

    def check_batch_completion(self, s: Session, batch_id: str) -> None:
        complete_batch(s, batch_id)
