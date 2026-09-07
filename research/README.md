# Quarantined Research Surfaces & Evaluation Harnesses

> **NOTICE: QUARANTINED RESEARCH SURFACE — NOT PART OF COUNSELCLEAR COMMERCIAL DISTRIBUTION.**

This directory contains standalone experimental evaluation harnesses, setup scripts, and adapters that interface with external third-party research projects:
- **CtrlRegen** (`mertizci/noai-watermark`): Experimental pixel-domain watermark removal. Note: Upstream repository does not supply an open-source license (treated as all-rights-reserved).
- **Reverse-SynthID** (`aloshdenny/reverse-SynthID`): Experimental detector/scorer for SynthID watermarking. Note: Upstream is licensed strictly under a non-commercial Research License and is not affiliated with or endorsed by Google.
- **MarkLLM** (`THU-BPM/MarkLLM`): Research toolkit for LLM watermarking evaluation (Apache-2.0).
- **MarkDiffusion** (`MarkDiffusion`): Research evaluation toolkit for diffusion image watermarking (Apache-2.0).

## Architectural Isolation

1. **Excluded from Commercial Builds & Images**: None of the files in `research/` are copied into `service/Dockerfile.counselclear` or included in published release artifacts.
2. **No Upstream Source Vendored**: All harnesses import from user-provided local checkouts or PyPI environments at runtime; no third-party source is vendored or redistributed by this repository.
3. **Control Plane Decoupled**: The CounselClear product spine (`service/app/`, `web/`, `tools/`) does not import or depend upon any harness in this directory.
