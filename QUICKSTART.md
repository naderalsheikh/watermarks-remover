# ClearCounsel — Quick Start

> **For evaluators and pilot users.** You can have ClearCounsel running locally in under five minutes.

---

## Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Docker Desktop (or Docker Engine + Compose v2) | 24.x |
| An OpenAI-compatible API key | — |
| 4 GB free disk space | — |

---

## 1 — Clone & configure

```bash
git clone https://github.com/naderalsheikh/watermarks-remover.git
cd watermarks-remover
cp .env.example .env
```

Open `.env` and set your API key:

```
OPENAI_API_KEY=sk-...
```

Everything else has safe defaults for a local pilot.

---

## 2 — Start ClearCounsel

```bash
docker compose up
```

The first run pulls images (~2 GB). Subsequent starts take under 10 seconds.

Open **http://localhost:8501** in your browser — the ClearCounsel UI is ready.

---

## 3 — Remove provenance from a document

1. Drag-and-drop (or browse to) a file in the **Upload** panel.  
   Supported formats: `.docx`, `.pdf`, `.md`, `.html`, `.txt`
2. Click **Analyze** — ClearCounsel shows you every provenance signal it found.
3. Click **Sanitize** — download the clean document.

A session log is saved automatically for audit purposes.

---

## Sample files

The `samples/` directory contains ready-to-use test documents:

| File | What to expect |
|------|----------------|
| `samples/synthetic_engagement_letter.docx` | DOCX with Unicode zero-width characters + RSID metadata embedded |
| `samples/synthetic_engagement_letter.txt` | Plain-text version of the same document |

---

## Stopping

```bash
docker compose down
```

---

## Troubleshooting

**Port 8501 already in use?**  
Set `STREAMLIT_PORT=8502` in `.env` and restart.

**API errors?**  
Make sure `OPENAI_API_KEY` is set and the model specified in `OPENAI_MODEL` is accessible from your account.

**Need the full research/evaluation harness?**  
See `docs/PRODUCTION_GUIDE.md` and use `docker compose --profile upstream up`.

---

*ClearCounsel is designed for legal practitioners who need to submit AI-assisted work product free of provenance signals. It handles Unicode hygiene, C2PA metadata, and statistical fingerprints across all document formats a law office actually uses.*
