"""Database-owned claims, leases and fencing for the existing jobs queue."""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass

from sqlalchemy import extract, func, select, update
from sqlalchemy.exc import IntegrityError

from .audit import append_event, lock_matter
from .models import Job, JobQueue, _now

log = logging.getLogger("counselclear")


class LostLease(RuntimeError):
    pass


@dataclass(frozen=True)
class Claim:
    job_id: str
    token: str
    attempt: int


def database_now(s) -> int:
    if s.get_bind().dialect.name == "sqlite":
        return int(s.scalar(select(func.strftime("%s", "now"))))
    return int(s.scalar(select(extract("epoch", func.clock_timestamp()))))


def configure_queue(s, capacity: int) -> None:
    if s.get(JobQueue, "default") is None:
        try:
            with s.begin_nested():
                s.add(JobQueue(id="default", capacity=capacity))
                s.flush()
        except IntegrityError:
            pass
    row = s.execute(
        select(JobQueue)
        .where(JobQueue.id == "default")
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if row.capacity != capacity:
        raise ValueError(
            "job concurrency differs from the shared database capacity; stop workers before changing it"
        )
    s.commit()


def claim_job(s, job_id: str, lease_s: int) -> Claim | None:
    """Reserve both a job and shared capacity in a single transaction."""
    try:
        queue = s.execute(
            select(JobQueue).where(JobQueue.id == "default").with_for_update()
        ).scalar_one()
        # Expired running owners still occupy a slot until recovery fences
        # them. Claiming never silently evicts another worker.
        running = s.query(Job).filter(Job.status == "running", Job.lease_token.isnot(None)).count()
        if running >= queue.capacity:
            s.rollback()
            return None
        job = s.execute(
            select(Job)
            .where(Job.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if job is None or job.status != "queued":
            s.rollback()
            return None
        token = uuid.uuid4().hex
        job.status = "running"
        job.lease_token = token
        job.lease_expires_epoch = database_now(s) + lease_s
        job.attempt_number += 1
        claim = Claim(job.id, token, job.attempt_number)
        s.commit()
        return claim
    except BaseException:
        s.rollback()
        raise


def require_lease(s, job: Job, claim: Claim) -> None:
    if (
        job.id != claim.job_id
        or job.lease_token != claim.token
        or job.attempt_number != claim.attempt
        or job.status != "running"
        or (job.lease_expires_epoch or 0) <= database_now(s)
    ):
        raise LostLease("job attempt no longer owns an unexpired lease")


def renew_lease(s, claim: Claim, lease_s: int) -> bool:
    now = database_now(s)
    changed = s.execute(
        update(Job)
        .where(
            Job.id == claim.job_id,
            Job.lease_token == claim.token,
            Job.attempt_number == claim.attempt,
            Job.status == "running",
            Job.lease_expires_epoch > now,
        )
        .values(lease_expires_epoch=now + lease_s)
    ).rowcount
    s.commit()
    return bool(changed)


class Heartbeat:
    def __init__(self, sessions, claim: Claim, lease_s: int):
        self.sessions, self.claim, self.lease_s = sessions, claim, lease_s
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="job-lease-heartbeat")

    def __enter__(self):
        self.thread.start()
        return self

    def _run(self):
        while not self.stop_event.wait(min(5, self.lease_s / 3)):
            try:
                with self.sessions() as s:
                    if not renew_lease(s, self.claim, self.lease_s):
                        return
            except Exception:
                # Never manufacture a renewal during a database outage.
                # Expiry fences publication even if the worker still exits.
                log.exception("job lease renewal failed for %s", self.claim.job_id)

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join(timeout=6)


def record_execution(s, claim: Claim, result) -> None:
    job = s.execute(
        select(Job)
        .where(Job.id == claim.job_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    require_lease(s, job, claim)
    job.execution_receipt = {
        "rc": result.rc,
        "stderr_tail": result.stderr_tail,
        "timed_out": result.timed_out,
        "output_dir": str(result.output_dir) if result.output_dir is not None else None,
    }
    s.commit()


def recover_expired(s, *, max_attempts: int) -> int:
    """Fence expired owners; preserve live work and bound abandoned retries."""
    from .job_lifecycle import complete_batch, finish_release

    now = database_now(s)
    ids = list(
        s.execute(
            select(Job.id, Job.matter_id)
            .where(
                Job.status == "running", Job.lease_token.isnot(None), Job.lease_expires_epoch <= now
            )
            .order_by(Job.matter_id, Job.id)
        )
    )
    recovered = 0
    for job_id, matter_id in ids:
        lock_matter(s, matter_id)
        job = s.execute(
            select(Job)
            .where(Job.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        if job.status != "running" or (job.lease_expires_epoch or 0) > database_now(s):
            continue
        job.lease_token = None
        job.lease_expires_epoch = None
        if job.execution_receipt is not None or job.attempt_number < max_attempts:
            job.status = "queued"
            action = "job.interrupted"
        else:
            job.status = "failed"
            job.error = "worker ownership expired; retry limit reached"
            job.finished_utc = _now()
            action = f"job.{job.kind}"
        append_event(
            s,
            matter_id=job.matter_id,
            actor_id=job.requested_by or "job-recovery",
            action=action,
            payload={
                "job_id": job.id,
                "document_id": job.document_id,
                "status": job.status,
                "attempt": job.attempt_number,
                "reason": "lease_expired",
            },
            commit=False,
        )
        if job.status == "failed":
            finish_release(s, job, commit=False)
            complete_batch(s, job.batch_id, commit=False)
        recovered += 1
    s.commit()
    return recovered
