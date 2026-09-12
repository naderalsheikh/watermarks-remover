"""Injected attachment processor interface and the adapter's checks on it.

A processor turns one attachment's bytes into a policy-verified derivative
using the shared CounselClear engine. The adapter never trusts a processor's
word for it: :func:`released_result_problem` re-derives the digests and
compares the reported policy and verification evidence against the request,
the same way ``app.runner._validated_bundle`` re-checks a worker's bundle
before the API records it.

M1 implementations and the integrated durable bridge:

- :class:`app.mail.engine_processor.LocalEngineProcessor` runs the real
  engine (``engine_api.clean_to_bundle``) in-process. It is the correct
  *engine* contract but not the production *isolation* contract; see its
  docstring.
- :class:`app.mail.durable_processor.DurableAttachmentProcessor` submits
  retained attachment jobs through the shared dispatcher and runner. It requires
  an explicit tenant/matter/service binding; it is not a mail listener.
- :class:`app.mail.synthetic.SyntheticDeterministicProcessor` is a test
  double. Its results carry ``verification="synthetic"`` and the adapter
  refuses them unless explicitly told it is running a test or demo.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Protocol

from .contract import PolicyReference, TrustedCallerContext, Verification

ProcessStatus = Literal["released", "refused", "failed", "unavailable"]


class ProcessorUnavailable(RuntimeError):
    """The processor could not be reached or could not accept work.

    Raised (or reported via ``status="unavailable"``) for transient conditions:
    queue full, engine not running, storage not mounted. The adapter holds
    the message as retryable; it never releases the original instead.
    """


@dataclass(frozen=True)
class ProcessRequest:
    """One attachment for the processor.

    ``engine_name`` is the filename the engine should classify by. It is
    derived by the adapter from the *sniffed* format and only reuses the
    sender's filename when the sender's extension agrees with the bytes.
    It is a display/classification name, never a filesystem path.
    """

    part_id: str
    display_name: str | None
    engine_name: str
    content: bytes
    source_sha256: str
    detected_format: str
    policy: PolicyReference
    caller: TrustedCallerContext


@dataclass(frozen=True)
class ProcessResult:
    status: ProcessStatus
    source_sha256: str
    output: bytes | None = None
    output_sha256: str | None = None
    output_bytes: int | None = None
    output_name: str | None = None
    policy: PolicyReference | None = None
    verification: Verification = "none"
    evidence_ref: str | None = None
    detail: str = ""
    processor: str = ""


class AttachmentProcessor(Protocol):
    """Anything that can process one attachment under a policy."""

    name: str

    def process(self, request: ProcessRequest) -> ProcessResult: ...


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def released_result_problem(
    request: ProcessRequest, result: ProcessResult, *, allow_synthetic: bool
) -> str | None:
    """Return why a ``released`` result cannot be used, or ``None`` if it can.

    Mirrors the trusted parent's bundle validation: the processor must have
    worked on exactly the bytes it was given, must report an output whose
    digest and size match the bytes it returns, must have applied the
    requested policy id and version, and must carry verification evidence
    the adapter is allowed to accept.
    """
    if result.status != "released":
        return f"status is {result.status}, not released"
    if result.source_sha256 != request.source_sha256:
        return "processor source digest differs from the submitted attachment"
    if not result.output:
        return "released result has no output bytes"
    actual_sha = sha256_hex(result.output)
    if result.output_sha256 != actual_sha:
        return "processor output digest differs from the returned bytes"
    if result.output_bytes != len(result.output):
        return "processor output size differs from the returned bytes"
    if result.policy is None:
        return "released result names no policy"
    if (
        result.policy.policy_id != request.policy.policy_id
        or result.policy.version != request.policy.version
    ):
        return "processor applied a different policy id or version"
    if result.verification == "engine_verified":
        return None
    if result.verification == "synthetic":
        if allow_synthetic:
            return None
        return "synthetic processor result is not accepted outside tests or the labeled demo"
    return "released result carries no verification evidence"
