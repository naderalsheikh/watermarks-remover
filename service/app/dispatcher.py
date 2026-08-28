"""In-process background dispatcher for Batch child jobs (PR 31).

Single-API-process safe only: the concurrency cap and the poll loop are
both purely in-process state (a ThreadPoolExecutor plus an in-memory
in-flight set). Running more than one API process/replica against a
shared database would let each process independently dispatch up to
``max_concurrent`` jobs, so the *effective* global concurrency becomes
``replicas * max_concurrent``, not the configured cap — there is no
shared lease coordinating dispatchers across processes.

The per-job claim itself (a conditional ``UPDATE ... WHERE
status='queued'``) *is* safe under concurrent processes — two
dispatchers, in the same process or different ones, can never both
execute the same job, so correctness holds under multi-replica
operation even though the concurrency bound doesn't. Do not run more
than one API process against a shared database until a cross-process
lease is added; see docs/COUNSELCLEAR_DESIGN.md's PR 31 entry and
docs/COUNSELCLEAR_PRODUCTION.md.

No Redis/Celery/broker: the ``jobs`` table itself is the durable queue,
per the approved proposal — this fills in the "Product MVP: in-process"
tier docs/COUNSELCLEAR_DESIGN.md's architecture diagram already
anticipated but left unimplemented.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import func, update
from sqlalchemy.orm import Session

from .audit import append_event
from .config import Config
from .models import Batch, Job, Release, _now
from .runner import run_job, sync_job

log = logging.getLogger("counselclear")


def sync_release(s: Session, job: Job) -> None:
    """A Job's sibling Release (if any -- most jobs have none, since not
    every sanitize path goes through the Release-wrapping /releases
    route) completes the moment ITS OWN Job finishes, independent of
    anything else. Deliberately never folded into check_batch_completion
    below: "batch completed" and "this one release completed" are
    different events on purpose -- see Release's own docstring in
    models.py.

    A free function, not a BatchDispatcher method (it never touches
    dispatcher state) -- so main.py's own two other Job-terminal paths
    that bypass the dispatcher's normal per-job completion flow
    (cancel_batch's bulk cancel, _sweep_orphaned_jobs' boot-time bulk
    fail) can call it directly too, instead of leaving their own sibling
    Release rows stuck "queued" forever with no release.terminal event.
    """
    release = s.query(Release).filter(Release.job_id == job.id).one_or_none()
    if release is None:
        return
    release.status = job.status
    release.finished_utc = job.finished_utc
    append_event(
        s,
        matter_id=job.matter_id,
        actor_id=release.requested_by,
        action="release.terminal",
        payload={"release_id": release.id, "job_id": job.id, "status": job.status},
    )


class BatchDispatcher:
    """Polls for queued batch children and runs them on a bounded pool.

    Mirrors main.py's own ``_execute_job`` pattern (one long-lived
    session held across the blocking worker call) so batch execution
    behaves identically to the synchronous single-document/bulk paths
    it reuses ``run_job``/``sync_job`` from.
    """

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
            q = s.query(Job.id).filter(Job.status == "queued", Job.batch_id.isnot(None))
            if exclude:
                q = q.filter(~Job.id.in_(exclude))
            job_ids = [row[0] for row in q.order_by(Job.created_utc).all()]
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
            batch_ids = [row[0] for row in s.query(Batch.id).filter(Batch.finished_utc.is_(None)).all()]
            for batch_id in batch_ids:
                self.check_batch_completion(s, batch_id)

    def _run_one(self, job_id: str) -> None:
        try:
            self._run_one_inner(job_id)
        finally:
            with self._lock:
                self._in_flight.discard(job_id)

    def _run_one_inner(self, job_id: str) -> None:
        # Atomic claim: run_job itself sets job.status = "running"
        # unconditionally (no compare-and-swap), so the dispatcher must do
        # its own conditional UPDATE first -- this is what actually
        # prevents two racing claims (two threads in this process, or two
        # processes sharing the database) from both executing the same job.
        with self._session_factory() as s:
            claimed = s.execute(
                update(Job).where(Job.id == job_id, Job.status == "queued").values(status="running")
            ).rowcount
            s.commit()
            if not claimed:
                return
            job = s.get(Job, job_id)
            kind = job.kind
            batch_id = job.batch_id

        s2 = self._session_factory()
        try:
            try:
                res = run_job(self._cfg, s2, job_id, kind=kind, storage=self._storage)
                sync_job(s2, job_id, res)
            except Exception as e:
                # run_job/sync_job already have their own internal error
                # handling for the failures they anticipate (worker
                # timeout, bad launch config, ...) -- this is the backstop
                # for something they didn't: an unexpected exception here
                # would otherwise leave the job stuck at "running" forever
                # (it was already claimed above) and, worse, the batch
                # polling forever since nothing would ever check it for
                # completion again.
                log.exception("batch dispatcher: job %s raised unexpectedly", job_id)
                s2.rollback()
                job = s2.get(Job, job_id)
                if job is not None and job.status not in ("done", "refused", "failed"):
                    job.status = "failed"
                    job.error = f"internal dispatcher error: {type(e).__name__}: {e}"[:1000]
                    job.finished_utc = _now()
                    s2.commit()
            finished = s2.get(Job, job_id)
            batch = s2.get(Batch, batch_id)
            try:
                self._append_child_audit(s2, finished, batch)
                sync_release(s2, finished)
            except Exception:
                log.exception("batch dispatcher: job %s finalization raised unexpectedly", job_id)
                s2.rollback()
            finally:
                self.check_batch_completion(s2, batch_id)
        finally:
            s2.close()

    def _append_child_audit(self, s: Session, job: Job, batch: Batch | None) -> None:
        if batch is None:  # defensive -- batch_id is a real FK, should never be missing
            return
        result = job.result_json or {}
        if job.kind == "sanitize":
            actions = (result.get("manifest") or {}).get("actions") or []
            no_decision_count = sum(1 for a in actions if self._no_decision_marker in a)
            append_event(
                s,
                matter_id=job.matter_id,
                actor_id=batch.requested_by,
                action="job.sanitize",
                payload={
                    "job_id": job.id,
                    "document_id": job.document_id,
                    "batch_id": batch.id,
                    "policy_id": job.policy_id,
                    "status": job.status,
                    "verification_pass": result.get("verification_pass"),
                    "no_decision_count": no_decision_count,
                },
            )
        else:
            append_event(
                s,
                matter_id=job.matter_id,
                actor_id=batch.requested_by,
                action="job.inspect",
                payload={
                    "job_id": job.id,
                    "document_id": job.document_id,
                    "batch_id": batch.id,
                    "status": job.status,
                    "findings_count": len(result.get("findings") or []),
                },
            )

    def check_batch_completion(self, s: Session, batch_id: str) -> None:
        """Fire batch.completed exactly once, the moment every child of
        this batch has left queued/running -- a no-op if the batch isn't
        actually done yet, or was already marked done.

        Public (not `_run_one_inner`-only) because a child can also leave
        queued/running from outside the dispatcher's own run loop: a
        cancel that fails every still-queued child (main.py's
        cancel_batch), or the boot orphan sweep failing a running child
        after a restart (main.py's _sweep_orphaned_jobs). Both call this
        directly so a batch whose last child finishes that way still gets
        marked complete and still gets its batch.completed audit event,
        instead of polling forever.
        """
        remaining = (
            s.query(Job)
            .filter(Job.batch_id == batch_id, Job.status.in_(("queued", "running")))
            .count()
        )
        if remaining:
            return
        # Atomic claim on the batch, same reasoning as the per-job claim
        # above: guards against two children finishing close enough
        # together that both observe remaining == 0 and both try to fire
        # batch.completed.
        claimed = s.execute(
            update(Batch)
            .where(Batch.id == batch_id, Batch.finished_utc.is_(None))
            .values(finished_utc=_now())
        ).rowcount
        s.commit()
        if not claimed:
            return
        batch = s.get(Batch, batch_id)
        counts = {"done": 0, "refused": 0, "failed": 0}
        for status, n in (
            s.query(Job.status, func.count(Job.id))
            .filter(Job.batch_id == batch_id)
            .group_by(Job.status)
            .all()
        ):
            counts[status] = n
        append_event(
            s,
            matter_id=batch.matter_id,
            actor_id=batch.requested_by,
            action="batch.completed",
            payload={"batch_id": batch_id, "total": batch.total, **counts},
        )
