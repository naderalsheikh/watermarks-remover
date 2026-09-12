"""Publish job results and their custody records in one database transaction.

Worker files are private until the validated references commit with the job,
release and audit records. A failed transaction leaves the job nonterminal;
the same worker result can be reconciled again without rerunning the engine.
"""

from __future__ import annotations

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .audit import _terminal_hash_facts, append_event, lock_matter
from .job_queue import Claim, LostLease, database_now, require_lease
from .models import AuditEvent, Batch, Job, Release, _now
from .runner import RunnerResult, sync_job

TERMINAL = ("done", "refused", "failed")


def complete_batch(s: Session, batch_id: str | None, *, commit: bool = True) -> None:
    if batch_id is None:
        return
    s.flush()
    batch = s.get(Batch, batch_id)
    if batch is None:
        return
    lock_matter(s, batch.matter_id)
    remaining = s.query(Job).filter(Job.batch_id == batch_id, Job.status.notin_(TERMINAL)).count()
    if remaining:
        return
    claimed = s.execute(
        update(Batch)
        .where(Batch.id == batch_id, Batch.finished_utc.is_(None))
        .values(finished_utc=_now())
    ).rowcount
    if claimed:
        counts = {"done": 0, "refused": 0, "failed": 0}
        for status, count in (
            s.query(Job.status, func.count(Job.id))
            .filter(Job.batch_id == batch_id)
            .group_by(Job.status)
        ):
            counts[status] = count
        append_event(
            s,
            matter_id=batch.matter_id,
            actor_id=batch.requested_by,
            action="batch.completed",
            payload={"batch_id": batch.id, "total": batch.total, **counts},
            commit=False,
        )
    if commit:
        s.commit()


def finish_release(s: Session, job: Job, *, commit: bool = True) -> AuditEvent | None:
    release = s.query(Release).filter(Release.job_id == job.id).one_or_none()
    if release is None or release.status in TERMINAL:
        return None
    release.status = job.status
    release.finished_utc = job.finished_utc
    event = append_event(
        s,
        matter_id=job.matter_id,
        actor_id=release.requested_by,
        action="release.terminal",
        payload={"release_id": release.id, "job_id": job.id, "status": job.status},
        commit=False,
    )
    if commit:
        s.commit()
    return event


def finalize_job(
    s: Session,
    job_id: str,
    result: RunnerResult,
    *,
    actor_id: str,
    no_decision_marker: str,
    claim: Claim | None = None,
) -> int | None:
    """Idempotent terminal publication; failures roll back the whole unit."""
    try:
        initial = s.get(Job, job_id)
        if initial is None:
            raise ValueError("job is missing")
        lock_matter(s, initial.matter_id)
        job = s.execute(
            select(Job)
            .where(Job.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        if job.status in TERMINAL:
            # Historical terminal records are not silently reconstructed.
            s.commit()
            return None
        if claim is not None:
            require_lease(s, job, claim)
        elif job.lease_token is not None:
            raise LostLease("a leased job requires its owning attempt to finalize")
        sync_job(s, job_id, result, commit=False)
        body = job.result_json or {}
        payload = {"job_id": job.id, "document_id": job.document_id, "status": job.status}
        if job.batch_id:
            payload["batch_id"] = job.batch_id
        if job.kind == "sanitize":
            actions = (body.get("manifest") or {}).get("actions") or []
            payload.update(
                policy_id=job.policy_id,
                verification_pass=body.get("verification_pass"),
                no_decision_count=sum(no_decision_marker in a for a in actions),
                **_terminal_hash_facts(job),
            )
        else:
            payload["findings_count"] = len(body.get("findings") or [])
        append_event(
            s,
            matter_id=job.matter_id,
            actor_id=actor_id,
            action=f"job.{job.kind}",
            payload=payload,
            commit=False,
        )
        release_event = finish_release(s, job, commit=False)
        complete_batch(s, job.batch_id, commit=False)
        terminal_seq = release_event.seq if release_event is not None else None
        if claim is not None and (job.lease_expires_epoch or 0) <= database_now(s):
            raise LostLease("lease expired during terminal publication")
        job.lease_token = None
        job.lease_expires_epoch = None
        s.commit()
        return terminal_seq
    except BaseException:
        s.rollback()
        raise
