# Third-party notices

CounselClear's published container image redistributes the Python packages
below. This file exists to satisfy their attribution terms. It is generated
from the metadata of the exact pinned versions in
`service/requirements-app.txt` rather than written by hand, and
`tests/test_image_license_compliance.py` fails if the two drift apart.

Nothing here restricts how CounselClear itself may be used. It records what
travels inside the image and under what terms.

| Package | Version | Licence |
|---|---|---|
| `fastapi` | 0.141.1 | MIT |
| `uvicorn` | 0.52.4 | BSD-3-Clause |
| `SQLAlchemy` | 2.0.52 | MIT |
| `argon2-cffi` | 25.1.0 | MIT |
| `python-multipart` | 0.0.32 | Apache-2.0 |
| `alembic` | 1.16.5 | MIT |
| `psycopg` | 3.2.13 | LGPL-3.0-only |
| `psycopg-binary` | 3.2.13 | LGPL-3.0-only |
| `PyJWT` | 2.13.0 | MIT |
| `cryptography` | 50.0.0 | Apache-2.0 OR BSD-3-Clause |
| `boto3` | 1.43.78 | Apache-2.0 |

Full licence texts ship inside each package's own distribution directory in
the image, which is where the authoritative text for each one lives.

## Apache-2.0 NOTICE propagation

Apache-2.0 §4(d) requires a redistributed work to carry the NOTICE text of
any Apache-licensed component that ships one:

> boto3
> Copyright 2013-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

## Copyleft components

`psycopg`, `psycopg-binary`

`psycopg` is LGPL-3.0-only -- the only copyleft terms in the shipped stack,
and the only ones imposing an obligation beyond retaining a notice.

CounselClear uses it as a PostgreSQL driver imported at runtime through
Python's normal import machinery. It is not statically linked, not vendored
and not modified, and a recipient may replace it in the image with their own
build of the same library, which is what LGPL-3.0 §4(d)(1) exists to
guarantee.

The driver ships even in SQLite-only deployments so that setting
`COUNSELCLEAR_DATABASE_URL` to a `postgresql+psycopg://` URL works without a
rebuild (see the comment beside the pin). A deployment that wants no
copyleft component in its image can drop the `psycopg[binary]` pin and
rebuild; SQLite mode never imports it.

## CounselClear itself

Licensed MIT -- see `LICENSE`, shipped at `/app/LICENSE` in the image.

---

_Generated 2026-09-05 by `tools/generate_third_party_notices.py`. Regenerate
whenever `service/requirements-app.txt` changes._
