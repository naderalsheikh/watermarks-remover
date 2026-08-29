```
_ _ _ ____ ___ ____ ____ _  _ ____ ____ _  _ ____    ____ ____ _  _ ____ _  _ ____ ____
| | | |__|  |  |___ |__/ |\/| |__| |__/ |_/  [__  __ |__/ |___ |\/| |  | |  | |___ |__/
|_|_| |  |  |  |___ |  \ |  | |  | |  \ | \_ ___]    |  \ |___ |  | |__|  \/  |___ |  \
```

# CounselClear / watermarks-remover

<!-- logo: figlet -d .figlet -f cybermedium -w 120 "watermarks-remover" -->

[![CI](https://github.com/guillaumemeyer/watermarks-remover/actions/workflows/ci.yml/badge.svg)](https://github.com/guillaumemeyer/watermarks-remover/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/guillaumemeyer/watermarks-remover)](https://github.com/guillaumemeyer/watermarks-remover/releases)
[![Stars](https://img.shields.io/github/stars/guillaumemeyer/watermarks-remover)](https://github.com/guillaumemeyer/watermarks-remover/stargazers)
[![Forks](https://img.shields.io/github/forks/guillaumemeyer/watermarks-remover)](https://github.com/guillaumemeyer/watermarks-remover/forks)

This repository currently contains **two distinct surfaces**:

1. **CounselClear**: the Release Gate product for policy-governed document release, custody records, verification, and offline review artifacts.
2. **`watermarks-remover` upstream utility**: the older watermark-removal and detection service plus optional research harnesses.

If you are evaluating or deploying the current product direction, start with **CounselClear**, not the upstream utility.

## Start here

If your goal is the current product, use only these surfaces:

- [CounselClear quickstart](#counselclear-default-path)
- [`docs/counselclear-eval-runbook.md`](docs/counselclear-eval-runbook.md)
- [`tools/counselclear_airlock.py`](tools/counselclear_airlock.py)
- [`tools/counselclear_verify_release_packet.py`](tools/counselclear_verify_release_packet.py)

Everything after [Legacy upstream utility and research surfaces](#legacy-upstream-utility-and-research-surfaces) is retained source history and research infrastructure, not the default product path.

## CounselClear default path

Primary surfaces:

- `service/app/` — API, releases, audit chain, certificates, batches
- `web/` — Release Gate UI
- `service/Dockerfile.counselclear` — default product image
- `tools/counselclear_airlock.py` — scriptable release workflow
- `tools/counselclear_verify_release_packet.py` — offline verifier

Start the product stack:

```bash
docker compose up --build -d
```

That brings up CounselClear on `http://127.0.0.1:8443`.

For local development outside Docker:

```bash
COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 \
uvicorn app_launcher:app --app-dir service --host 127.0.0.1 --port 8443

cd web
npm run dev
```

Then open `http://localhost:3000`.

The current product walkthrough is in [`docs/counselclear-eval-runbook.md`](docs/counselclear-eval-runbook.md).

## Legacy upstream utility and research surfaces

The upstream `watermarks-remover` utility and its optional research harnesses
remain in this repo for reference and internal work, but they are not the
default CounselClear product path.

See [`docs/UPSTREAM_UTILITY_LEGACY.md`](docs/UPSTREAM_UTILITY_LEGACY.md) for:

- the legacy `wr-core` HTTP utility
- optional detector and watermark-research harnesses
- upstream utility Docker/compose details
- benchmark and release-history material for the pre-CounselClear surface

If you are evaluating or deploying CounselClear, you can ignore that document.

## License

MIT — see [LICENSE](LICENSE).
