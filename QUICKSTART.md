# CounselClear — 5-Minute Evaluation

For a law-firm IT/security reviewer. You need only **Docker** and **Python 3**
already installed. Every command runs from this repo's root folder. Nothing
leaves your machine: the stack binds to `127.0.0.1` only.

CounselClear is an evidentiary-custody tool. It does **not** promise a document
is "clean" or that every AI mark is gone. It produces a signed record of what
was **cleared, stripped, kept, refused, or found out of scope** under a named
policy — that record is the product.

### 1. Start the stack (one command)

```bash
COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 docker compose --profile legal up -d
```

This launches the CounselClear product stack (API at `http://127.0.0.1:8443`).
It is the default surface — `docker compose up -d` starts the same services;
`--profile legal` is the explicit, self-documenting alias.

### 2. Run the airlock on a document

Seed a demo matter with synthetic fixtures, then send one through the airlock
(both are thin HTTP clients — no client data leaves the container):

```bash
COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 python3 tools/seed_eval_matter.py \
    --base-url http://127.0.0.1:8443          # prints a matter id + 3 outcomes

COUNSELCLEAR_LOCAL_PASSWORD=evalpass123 python3 tools/counselclear_airlock.py \
    --base-url http://127.0.0.1:8443 --matter-id <MATTER_ID> \
    --file samples/synthetic_engagement_letter.txt \
    --recipient-type opposing_counsel --output-dir ./airlock-out
```

### 3. Read the release manifest (why it matters legally)

The airlock writes a **release packet** into `./airlock-out/`. Open its
`release_result.json` / manifest. It records, per finding, an evidence-bound
outcome — *"Stripped under policy X"*, *"Kept because reason Y"*, *"Refused by
policy"*, *"Out of scope for this policy"*, *"Verification passed for these
checks"* — alongside the original vs. derivative SHA-256 hashes, the policy id
and version, and the processor identity. That is a defensible chain of custody
you can file alongside a closing binder or production log: it proves exactly
what happened to the document, rather than asserting the document is safe.

Verify any packet offline (expect `INTERNALLY CONSISTENT`, plus the honest
`NOT EXTERNALLY ANCHORED` disclosure):

```bash
python3 tools/counselclear_verify_release_packet.py ./airlock-out
```

### 4. Stop and clean up (one command)

```bash
docker compose --profile legal down -v      # stops services and removes volumes
```
