"""Attachment processor backed by the real CounselClear engine, in-process.

``LocalEngineProcessor`` runs ``engine_api.clean_to_bundle`` (inspect ->
plan -> apply -> verify -> write-once bundle) on one attachment in a private
temporary directory and maps the resulting custody manifest onto
:class:`ProcessResult`, applying the same checks ``app.runner._validated_bundle``
applies to a worker bundle before the API records it. Its results carry
``verification="engine_verified"`` because the engine's own
``verify_derivative`` gate passed and the manifest binds original and
derivative digests.

What it is *not*: the production isolation path. The API executes jobs in a
one-shot worker subprocess or a hardened container (``app.runner``) precisely
so a hostile document cannot reach mail credentials, the database, or other
tenants' files. This class parses attachments inside the calling process.
Use it for local fixtures, engine-backed tests, and the labeled demo. A
production mail gateway must submit attachment jobs through the durable
job/runner path; the interface that path still lacks is described in
``docs/COUNSELCLEAR_MAIL_ADAPTER.md``.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .contract import PolicyReference
from .processor import ProcessRequest, ProcessResult, sha256_hex


@dataclass
class LocalEngineProcessor:
    name: str = "local-engine-in-process"
    operator_id: str = "mail-adapter"
    scan: bool = True

    def process(self, request: ProcessRequest) -> ProcessResult:
        from engine_api import clean_to_bundle

        if self.scan:
            from ..malware import get_scanner

            verdict = get_scanner().scan(request.content, request.engine_name)
            if not verdict.clean:
                return ProcessResult(
                    status="refused",
                    source_sha256=request.source_sha256,
                    policy=request.policy,
                    detail=f"malware scan ({verdict.scanner}): {verdict.detail}"[:300],
                    processor=self.name,
                )

        with tempfile.TemporaryDirectory(prefix="cc-mail-") as tmp:
            root = Path(tmp)
            src = root / "input" / request.engine_name
            src.parent.mkdir()
            src.write_bytes(request.content)
            bundle_dir = root / "bundle"
            try:
                result = clean_to_bundle(
                    src,
                    bundle_dir,
                    policy_id=request.policy.policy_id,
                    operator_id=self.operator_id,
                    matter_id=None,
                    retain_original=False,
                )
            except Exception as exc:
                return _failure(request, exc, self.name)
            try:
                return _released(request, result, bundle_dir, self.name)
            except _ContractMismatch as exc:
                return ProcessResult(
                    status="failed",
                    source_sha256=request.source_sha256,
                    detail=f"engine bundle contract mismatch: {exc}",
                    processor=self.name,
                )


class _ContractMismatch(ValueError):
    pass


def _failure(request: ProcessRequest, exc: Exception, name: str) -> ProcessResult:
    import custody as custody_mod

    message = str(exc)
    if isinstance(exc, custody_mod.CustodyError) and message.startswith("plan refused"):
        return ProcessResult(
            status="refused",
            source_sha256=request.source_sha256,
            policy=request.policy,
            detail=message[:300],
            processor=name,
        )
    return ProcessResult(
        status="failed",
        source_sha256=request.source_sha256,
        detail=f"{type(exc).__name__}: {message}"[:300],
        processor=name,
    )


def _released(request: ProcessRequest, result: dict, bundle_dir: Path, name: str) -> ProcessResult:
    manifest = result.get("manifest_data")
    if not isinstance(manifest, dict):
        raise _ContractMismatch("no manifest")
    original = manifest.get("original")
    derivative = manifest.get("derivative")
    policy = manifest.get("policy")
    verification = manifest.get("verification")
    if not all(isinstance(v, dict) for v in (original, derivative, policy, verification)):
        raise _ContractMismatch("manifest lacks custody metadata")
    if (
        verification.get("pass") is not True
        or result.get("verification", {}).get("pass") is not True
    ):
        raise _ContractMismatch("verification did not pass")
    if (
        original.get("filename") != request.engine_name
        or original.get("sha256") != request.source_sha256
        or original.get("bytes") != len(request.content)
    ):
        raise _ContractMismatch("manifest original does not match the submitted attachment")
    if policy.get("id") != request.policy.policy_id:
        raise _ContractMismatch("manifest policy id differs from the request")
    version = policy.get("version")
    if not isinstance(version, int) or version != request.policy.version:
        raise _ContractMismatch("manifest policy version differs from the request")

    derivative_path = Path(result["derivative"])
    try:
        derivative_path.resolve().relative_to((bundle_dir / "derivative").resolve())
    except ValueError as exc:
        raise _ContractMismatch("derivative outside the bundle") from exc
    if derivative_path.name != derivative.get("filename"):
        raise _ContractMismatch("derivative name differs from manifest")
    output = derivative_path.read_bytes()
    output_sha = sha256_hex(output)
    if derivative.get("sha256") != output_sha or derivative.get("bytes") != len(output):
        raise _ContractMismatch("derivative differs from its custody hash or size")

    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return ProcessResult(
        status="released",
        source_sha256=request.source_sha256,
        output=output,
        output_sha256=output_sha,
        output_bytes=len(output),
        output_name=derivative_path.name,
        policy=PolicyReference(str(policy["id"]), version),
        verification="engine_verified",
        evidence_ref=f"manifest:sha256:{sha256_hex(manifest_bytes)}",
        detail="engine verify_derivative passed; manifest digests bound",
        processor=name,
    )
