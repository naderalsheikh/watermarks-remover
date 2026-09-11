"""TEST DOUBLE: a deterministic attachment processor that is NOT the engine.

``SyntheticDeterministicProcessor`` exists so the adapter's MIME handling,
matching, replacement and re-verification can be exercised without the
document engine. Its "derivative" is a synthetic byte string derived from the
input digest; it performs no inspection, cleaning or verification, and every
result it returns is tagged ``verification="synthetic"``. The adapter only
accepts such results when constructed with ``allow_synthetic=True``, which
tests and the labeled demo do and production code must not.

The ``mode`` argument makes the double misbehave on purpose so the adapter's
checks can be tested: refusals, failures, unavailability, and results whose
evidence contradicts the request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .processor import ProcessorUnavailable, ProcessRequest, ProcessResult, sha256_hex

Mode = Literal[
    "replace",
    "refuse",
    "fail",
    "unavailable",
    "raise_unavailable",
    "crash",
    "wrong_source_digest",
    "wrong_output_digest",
    "wrong_policy",
    "claim_engine_verified",
    "no_verification",
    "grow",
]

SYNTHETIC_PREFIX = b"%CounselClear-synthetic-derivative\n"


def synthetic_derivative(content: bytes) -> bytes:
    """The deterministic transformation: a marker line plus the input digest.

    Deliberately unrelated to any document format so nobody can mistake the
    output for a cleaned document.
    """
    return SYNTHETIC_PREFIX + sha256_hex(content).encode("ascii") + b"\n"


@dataclass
class SyntheticDeterministicProcessor:
    name: str = "synthetic-test-double"
    mode: Mode = "replace"
    calls: list[ProcessRequest] = field(default_factory=list)

    def process(self, request: ProcessRequest) -> ProcessResult:
        self.calls.append(request)
        if self.mode == "raise_unavailable":
            raise ProcessorUnavailable("synthetic queue is offline")
        if self.mode == "crash":
            raise RuntimeError("synthetic crash")
        if self.mode == "refuse":
            return ProcessResult(
                status="refused",
                source_sha256=request.source_sha256,
                policy=request.policy,
                detail="plan refused: synthetic refusal",
                processor=self.name,
            )
        if self.mode == "fail":
            return ProcessResult(
                status="failed",
                source_sha256=request.source_sha256,
                detail="synthetic failure",
                processor=self.name,
            )
        if self.mode == "unavailable":
            return ProcessResult(
                status="unavailable",
                source_sha256=request.source_sha256,
                detail="synthetic unavailable",
                processor=self.name,
            )

        output = synthetic_derivative(request.content)
        if self.mode == "grow":
            output = output + b"0" * (64 * 1024)
        result = ProcessResult(
            status="released",
            source_sha256=request.source_sha256,
            output=output,
            output_sha256=sha256_hex(output),
            output_bytes=len(output),
            output_name=_synthetic_name(request.engine_name),
            policy=request.policy,
            verification="synthetic",
            evidence_ref=f"synthetic:{request.part_id}",
            detail="synthetic transformation; no engine verification performed",
            processor=self.name,
        )
        if self.mode == "wrong_source_digest":
            return _with(result, source_sha256=sha256_hex(b"not the input"))
        if self.mode == "wrong_output_digest":
            return _with(result, output_sha256=sha256_hex(b"not the output"))
        if self.mode == "wrong_policy":
            from .contract import PolicyReference

            return _with(
                result,
                policy=PolicyReference(request.policy.policy_id, request.policy.version + 1),
            )
        if self.mode == "claim_engine_verified":
            # A double that lies about its evidence. The adapter must still
            # refuse it in production mode; in test mode this exercises the
            # verification-label plumbing only.
            return _with(result, verification="engine_verified")
        if self.mode == "no_verification":
            return _with(result, verification="none")
        return result


def _synthetic_name(engine_name: str) -> str:
    stem, dot, ext = engine_name.rpartition(".")
    return f"{stem}.synthetic.{ext}" if dot else f"{engine_name}.synthetic"


def _with(result: ProcessResult, **changes: object) -> ProcessResult:
    from dataclasses import replace

    return replace(result, **changes)
