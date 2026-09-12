"""Internal durable mail admission and outbox; never opens or sends SMTP.

A configured service binding and ACL checks guard every operation. The caller
must supply authenticated transport facts; this module is not an ingress
protocol and exposes no HTTP endpoints or caller-controlled trust flags.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..acl import has_perm
from ..audit import append_event, lock_matter
from ..job_queue import database_now
from ..models import MailSubmission
from ..storage import StorageError
from .adapter import MailAdapter
from .contract import AdapterLimits, AdapterRequest, Envelope, TrustedCallerContext
from .durable_processor import DurableAttachmentProcessor, TenantJobBinding


class MailStateError(RuntimeError):
    pass


class BindingDenied(MailStateError):
    pass


class SubmissionConflict(MailStateError):
    pass


class LeaseLost(MailStateError):
    pass


@dataclass(frozen=True)
class SubmissionView:
    id: str
    status: str
    retryable: bool
    reasons: tuple[str, ...]
    input_sha256: str
    output_sha256: str | None


@dataclass(frozen=True)
class ProcessingClaim:
    submission_id: str
    token: str = field(repr=False)
    attempt: int


@dataclass(frozen=True)
class DeliveryTicket:
    submission_id: str
    token: str = field(repr=False)
    raw: bytes = field(repr=False)
    envelope: Envelope = field(repr=False)
    sha256: str


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _text(value, name, limit=200):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ValueError(f"invalid {name}")
    return value


class MailSubmissionRegistry:
    def __init__(
        self,
        *,
        cfg,
        session_factory,
        storage,
        binding: TenantJobBinding,
        limits: AdapterLimits | None = None,
        max_recipients=1000,
        max_envelope_bytes=384_000,
        lease_s=60,
        delivery_timeout_s=300,
    ):
        if not 3 <= lease_s <= 3600 or not 3 <= delivery_timeout_s <= 3600:
            raise ValueError("invalid mail ownership timeout")
        if not 1 <= max_recipients <= 1000 or not 1 <= max_envelope_bytes <= 384_000:
            raise ValueError("invalid envelope bounds")
        _text(binding.policy.policy_id, "policy id", 128)
        self.cfg, self.sessions, self.storage, self.binding = cfg, session_factory, storage, binding
        self.limits = limits or AdapterLimits()
        self.max_recipients, self.max_envelope_bytes = max_recipients, max_envelope_bytes
        self.lease_s, self.delivery_timeout_s = lease_s, delivery_timeout_s

    def _authorize(self, s):
        b = self.binding
        if not all(has_perm(s, b.matter_id, b.actor_id, p) for p in ("read", "upload", "sanitize")):
            raise BindingDenied("mail service lacks the required matter permissions")

    def _bound_fields(self, row):
        return {
            "tenant": row.tenant_id,
            "matter": row.matter_id,
            "actor": row.actor_id,
            "request_id": row.request_id,
            "policy": [row.policy_id, row.policy_version],
            "transport": row.transport,
            "peer": row.peer_identity,
            "envelope": row.envelope,
            "input": [row.input_sha256, row.input_bytes],
            "limits": row.limits,
            "unsupported_parts": "hold",
        }

    def _row(self, s, submission_id):
        self._authorize(s)
        lock_matter(s, self.binding.matter_id)
        row = s.get(MailSubmission, submission_id, populate_existing=True)
        b = self.binding
        if row is None or (row.tenant_id, row.matter_id, row.actor_id) != (
            b.tenant_id,
            b.matter_id,
            b.actor_id,
        ):
            raise BindingDenied("submission is outside the configured service binding")
        if (row.policy_id, row.policy_version) != (b.policy.policy_id, b.policy.version):
            raise SubmissionConflict("submission policy differs from the configured binding")
        if row.binding_sha256 != _digest(self._bound_fields(row)):
            raise SubmissionConflict("retained admission facts changed")
        return row

    @staticmethod
    def _view(row):
        return SubmissionView(
            row.id,
            row.status,
            row.retryable,
            tuple(row.reasons),
            row.input_sha256,
            row.output_sha256,
        )

    def _event(self, s, row, action):
        # No addresses, message headers/content, storage paths, or raw request IDs.
        append_event(
            s,
            matter_id=row.matter_id,
            actor_id=row.actor_id,
            action="mail." + action,
            payload={
                "submission_id": row.id,
                "tenant_sha256": _digest(row.tenant_id),
                "request_key": row.request_key,
                "binding_sha256": row.binding_sha256,
                "status": row.status,
                "attempt": row.attempt,
                "input_sha256": row.input_sha256,
                "output_sha256": row.output_sha256,
                "recipient_count": len(row.envelope["rcpt_to"]),
            },
            commit=False,
        )

    def _key(self, row, name):
        return f"{self.cfg.org}/matters/{row.matter_id}/mail/{row.id}/{name}"

    def admit(self, raw: bytes, envelope: Envelope, caller: TrustedCallerContext) -> SubmissionView:
        if not isinstance(raw, bytes) or not raw or len(raw) > self.limits.max_message_bytes:
            raise ValueError("mail input is empty or exceeds the configured bound")
        if not isinstance(envelope, Envelope) or len(envelope.rcpt_to) > self.max_recipients:
            raise ValueError("invalid or oversized envelope")
        env = {"mail_from": envelope.mail_from, "rcpt_to": list(envelope.rcpt_to)}
        if len(json.dumps(env, ensure_ascii=True).encode()) > self.max_envelope_bytes:
            raise ValueError("envelope exceeds its encoded byte bound")
        if any(
            any(ord(c) < 32 or ord(c) == 127 for c in address)
            for address in (envelope.mail_from, *envelope.rcpt_to)
        ):
            raise ValueError("envelope contains control characters")
        if not caller.is_trusted() or caller.tenant_id != self.binding.tenant_id:
            raise BindingDenied("transport context does not match the configured tenant")
        _text(caller.request_id, "transport request identity")
        _text(caller.transport, "transport")
        _text(caller.peer_identity, "authenticated peer")
        b = self.binding
        row = MailSubmission(
            id=uuid.uuid4().hex,
            tenant_id=b.tenant_id,
            request_key=_digest(caller.request_id),
            request_id=caller.request_id,
            matter_id=b.matter_id,
            actor_id=b.actor_id,
            policy_id=b.policy.policy_id,
            policy_version=b.policy.version,
            transport=caller.transport,
            peer_identity=caller.peer_identity,
            envelope=env,
            limits=asdict(self.limits),
            input_ref="",
            input_sha256=hashlib.sha256(raw).hexdigest(),
            input_bytes=len(raw),
            status="admitted",
            retryable=False,
            reasons=[],
            attempt=0,
        )
        row.binding_sha256 = _digest(self._bound_fields(row))
        try:
            with self.sessions() as s:
                self._authorize(s)
                lock_matter(s, b.matter_id)
                prior = s.scalar(
                    select(MailSubmission).where(
                        MailSubmission.tenant_id == b.tenant_id,
                        MailSubmission.request_key == row.request_key,
                    )
                )
                if prior is not None:
                    if prior.binding_sha256 != row.binding_sha256:
                        raise SubmissionConflict(
                            "transport request identity was already bound differently"
                        )
                    return self._view(self._row(s, prior.id))
                row.created_epoch = row.updated_epoch = database_now(s)
                row.input_ref = self.storage.write_once(self._key(row, "input.eml"), raw)
                s.add(row)
                self._event(s, row, "admitted")
                s.commit()
                return self._view(row)
        except IntegrityError:
            # Another matter can race the tenant-wide identity constraint.
            # Its transaction wins; this one leaves at most an unreferenced blob.
            with self.sessions() as s:
                self._authorize(s)
                prior = s.scalar(
                    select(MailSubmission).where(
                        MailSubmission.tenant_id == b.tenant_id,
                        MailSubmission.request_key == row.request_key,
                    )
                )
                if prior is None:
                    raise
                if prior.binding_sha256 != row.binding_sha256:
                    raise SubmissionConflict(
                        "transport request identity was already bound differently"
                    ) from None
                return self._view(self._row(s, prior.id))

    def get(self, submission_id) -> SubmissionView:
        with self.sessions() as s:
            return self._view(self._row(s, submission_id))

    def _expired(self, s, row):
        now = database_now(s)
        if row.status == "processing" and (row.lease_expires_epoch or 0) <= now:
            row.status, row.retryable, row.reasons = "held", True, ["processing_lease_expired"]
            row.lease_token = row.lease_expires_epoch = None
            row.updated_epoch = now
            self._event(s, row, "processing.expired")
        elif row.status == "submitted" and (row.delivery_expires_epoch or 0) <= now:
            row.status, row.retryable, row.reasons = (
                "ambiguous",
                False,
                ["delivery_outcome_unknown"],
            )
            row.updated_epoch = now
            self._event(s, row, "delivery.ambiguous")

    def recover(self, submission_id) -> SubmissionView:
        with self.sessions() as s:
            row = self._row(s, submission_id)
            self._expired(s, row)
            s.commit()
            return self._view(row)

    def claim(self, submission_id) -> ProcessingClaim | None:
        with self.sessions() as s:
            row = self._row(s, submission_id)
            self._expired(s, row)
            if row.status != "admitted" and not (row.status == "held" and row.retryable):
                s.commit()
                return None
            row.status, row.retryable = "processing", False
            row.lease_token = uuid.uuid4().hex
            row.attempt += 1
            row.updated_epoch = database_now(s)
            row.lease_expires_epoch = row.updated_epoch + self.lease_s
            claim = ProcessingClaim(row.id, row.lease_token, row.attempt)
            self._event(s, row, "processing.claimed")
            s.commit()
            return claim

    def _lease(self, s, row, claim):
        if (
            row.status != "processing"
            or row.lease_token != claim.token
            or row.attempt != claim.attempt
            or (row.lease_expires_epoch or 0) <= database_now(s)
        ):
            raise LeaseLost("mail processing no longer owns an unexpired lease")

    def renew(self, claim) -> None:
        with self.sessions() as s:
            row = self._row(s, claim.submission_id)
            self._lease(s, row, claim)
            row.lease_expires_epoch = database_now(s) + self.lease_s
            s.commit()

    @contextmanager
    def _heartbeat(self, claim):
        stop = threading.Event()

        def run():
            while not stop.wait(min(5, self.lease_s / 3)):
                try:
                    self.renew(claim)
                except Exception:
                    # Publication still checks expiry after any lost renewal.
                    return

        worker = threading.Thread(target=run, name="mail-lease-heartbeat", daemon=True)
        worker.start()
        try:
            yield
        finally:
            stop.set()
            worker.join(timeout=6)

    def _request(self, claim):
        with self.sessions() as s:
            row = self._row(s, claim.submission_id)
            self._lease(s, row, claim)
            ref, digest, size = row.input_ref, row.input_sha256, row.input_bytes
            envelope = Envelope(row.envelope["mail_from"], tuple(row.envelope["rcpt_to"]))
            caller = TrustedCallerContext(
                row.tenant_id, row.transport, True, row.request_id, row.peer_identity
            )
            limits = AdapterLimits(**row.limits)
        raw = self.storage.read_expected(ref, sha256=digest, size=size)
        return AdapterRequest(
            raw, envelope, caller, self.binding.policy, limits=limits, unsupported_parts="hold"
        )

    def _publish(self, claim, result):
        with self.sessions() as s:
            row = self._row(s, claim.submission_id)
            self._lease(s, row, claim)
            if result.decision not in {"release", "hold", "refuse"}:
                raise SubmissionConflict("invalid adapter decision")
            if result.releasable:
                out = result.outbound
                expected = Envelope(row.envelope["mail_from"], tuple(row.envelope["rcpt_to"]))
                if (
                    out.envelope != expected
                    or hashlib.sha256(out.raw).hexdigest() != out.sha256
                    or len(out.raw) > AdapterLimits(**row.limits).output_limit
                ):
                    raise SubmissionConflict("outbound bytes or envelope contradict admission")
                row.output_ref = self.storage.write_once(
                    self._key(row, f"outputs/{claim.token}.eml"), out.raw
                )
                row.output_sha256, row.output_bytes = out.sha256, len(out.raw)
                self._lease(s, row, claim)
                row.status = "released"
            else:
                if result.outbound is not None or result.decision == "release":
                    raise SubmissionConflict("blocked decision cannot carry outbound bytes")
                row.status = "held" if result.decision == "hold" else "refused"
            row.retryable = row.status == "held" and result.retryable
            row.reasons = [str(reason)[:200] for reason in result.reasons[:64]]
            row.updated_epoch = database_now(s)
            row.lease_token = row.lease_expires_epoch = None
            self._event(s, row, "decision")
            s.commit()
            return self._view(row)

    def process(self, submission_id, processor: DurableAttachmentProcessor) -> SubmissionView:
        if (
            not isinstance(processor, DurableAttachmentProcessor)
            or processor.binding != self.binding
            or processor.cfg.db_url() != self.cfg.db_url()
            or processor.cfg.data_root != self.cfg.data_root
        ):
            raise BindingDenied("coordinator requires the bound shared durable processor")
        claim = self.claim(submission_id)
        if claim is None:
            return self.get(submission_id)
        with self._heartbeat(claim):
            try:
                result = MailAdapter(processor).process(self._request(claim))
            except (StorageError, OSError):
                # Leave ownership intact: explicit expiry recovery can retry;
                # no fabricated successful result or permanently lost input.
                return self.get(submission_id)
            return self._publish(claim, result)

    def prepare_delivery(self, submission_id) -> DeliveryTicket:
        """Commit submitted BEFORE giving a future sender access to DATA bytes.

        Repeated calls cannot obtain a second send ticket. Even pre-DATA failure
        stays conservative: only acknowledgement or ambiguity can follow.
        """
        with self.sessions() as s:
            row = self._row(s, submission_id)
            if row.status != "released" or not row.output_ref or not row.output_sha256:
                raise SubmissionConflict("only a released submission can acquire a delivery ticket")
            raw = self.storage.read_expected(
                row.output_ref, sha256=row.output_sha256, size=row.output_bytes
            )
            if len(raw) > AdapterLimits(**row.limits).output_limit:
                raise SubmissionConflict("retained output exceeds its admission bound")
            row.status, row.delivery_token = "submitted", uuid.uuid4().hex
            row.updated_epoch = database_now(s)
            row.delivery_expires_epoch = row.updated_epoch + self.delivery_timeout_s
            ticket = DeliveryTicket(
                row.id,
                row.delivery_token,
                raw,
                Envelope(row.envelope["mail_from"], tuple(row.envelope["rcpt_to"])),
                row.output_sha256,
            )
            self._event(s, row, "delivery.submitted")
            s.commit()
            return ticket

    def acknowledge(self, ticket: DeliveryTicket, receipt_id: str) -> SubmissionView:
        _text(receipt_id, "trusted delivery acknowledgment")
        receipt_digest = _digest(receipt_id)
        with self.sessions() as s:
            row = self._row(s, ticket.submission_id)
            if row.delivery_token != ticket.token:
                raise LeaseLost("delivery ticket is not the retained owner")
            if row.status == "acknowledged" and row.acknowledgment_sha256 == receipt_digest:
                return self._view(row)
            if row.status != "submitted":
                raise SubmissionConflict("submission cannot accept a delivery acknowledgment")
            self._expired(s, row)
            if row.status == "submitted":
                row.status, row.acknowledgment_sha256 = "acknowledged", receipt_digest
                row.updated_epoch = database_now(s)
                self._event(s, row, "delivery.acknowledged")
            s.commit()
            return self._view(row)

    def mark_ambiguous(self, ticket: DeliveryTicket) -> SubmissionView:
        with self.sessions() as s:
            row = self._row(s, ticket.submission_id)
            if row.delivery_token != ticket.token:
                raise LeaseLost("delivery ticket is not the retained owner")
            if row.status == "ambiguous":
                return self._view(row)
            if row.status != "submitted":
                raise SubmissionConflict("only submitted mail can become delivery-ambiguous")
            row.status, row.retryable, row.reasons = (
                "ambiguous",
                False,
                ["delivery_outcome_unknown"],
            )
            row.updated_epoch = database_now(s)
            self._event(s, row, "delivery.ambiguous")
            s.commit()
            return self._view(row)
