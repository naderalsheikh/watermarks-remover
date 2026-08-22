# How word-choice text watermarks actually work

[`mark-classes.md`](mark-classes.md) and [`vendor-notes.md`](vendor-notes.md) name the schemes (KGW green-list, SynthID-Text / Tournament sampling, keyed-Gumbel / EXP) and cite the papers. This doc is the missing middle layer: what is actually happening to the *words*, in plain terms, with a worked example — so "statistical token-sampling watermark" stops being a phrase you take on faith.

## The core idea, before any math

At almost every point in a sentence, an LLM has many *equally reasonable* next words. After "the company reported ", it might say `strong`, `solid`, `steady`, `robust`, `healthy` growth — a human reader would accept any of them, and the model itself thinks they're all roughly as likely.

A word-choice watermark doesn't change *what* the model is allowed to say. It changes *which of the equally-good options wins*, using a rule that:

- looks like noise to a reader (there's no pattern like "always pick the shorter synonym"),
- is **reproducible** by anyone who has the secret key used to generate it — because the "random" tie-breaker isn't actually random, it's a hash of that key plus the last few words,
- and, averaged over hundreds of words, produces a statistically loud signal even though no single word looks wrong.

That's the whole trick. Two real families implement it differently.

## Mechanism 1: green-list bias (Kirchenbauer / KGW, and SynthID-Text's Tournament sampling is a cousin of this)

Before the model picks word number *t*, the generator:

1. Takes the last **H** words already written (H=4 is a common default) and the secret key, and hashes them together to get a seed.
2. Uses that seed to pseudo-randomly split the *entire vocabulary* into a "green list" (~50%) and a "red list" (~50%) — **just for this one position**. One word later, with a different H-word window, the split is completely different.
3. Adds a small bonus to every green-list word's score before sampling. Not a hard rule ("only green words allowed") — a nudge. Red-list words remain possible, just slightly less likely to win.

Do this at every position, and here's what falls out statistically: in **ordinary, unwatermarked** text, a word landing in "green" for its own position's arbitrary split is basically a coin flip — roughly 50% of words will happen to be green, because the split has nothing to do with how humans (or an unwatermarked model) actually write. In **watermarked** text, the bias means the *actual* green rate runs much higher — commonly 70-90%+ depending on how strong the bias is set.

A worked example (illustrative numbers, not a real key):

| # | Word actually written | Green-list membership at that position | 
|---|---|---|
| 1 | "quarterly" | green |
| 2 | "report" | red |
| 3 | "shows" | green |
| 4 | "steady" | green |
| 5 | "growth" | green |
| 6 | "across" | red |
| 7 | "every" | green |
| 8 | "region" | green |
| 9 | "we" | green |
| 10 | "track" | green |

8 of 10 green. For an unwatermarked sentence you'd expect roughly 5 of 10 (chance), so a run this lopsided is the tell — the more words you have, the sharper that statistic gets (a detector runs a proper binomial/z-test, not a raw percentage, but the percentage is the intuition).

**Detecting it** requires the key: recompute the green/red split at every position of the candidate text (you need the same hash function and the same H) and count how often the actual word landed green. **Removing it** (best-effort) means rewriting enough words that the new text's green rate drifts back down toward chance — which is exactly why Layer B needs a *substantial* rewrite, not a light touch-up (see the README's "what removing a text watermark costs" section: light edits leave most of the original word choices, and word choices are the whole carrier).

This repo's optional [`MarkLLM`](https://github.com/THU-BPM/MarkLLM) harness (`detect_text_watermark.py --scheme kgw`) implements exactly this — but only under a scheme/key **you** configured; it can't crack a vendor's production key.

## Mechanism 2: keyed-Gumbel / EXP sampling (Aaronson-style; ships in the open-source `arbi-serve` engine)

This one is subtler — it never removes any word from consideration, it changes *how the dice are rolled*.

Normal sampling: for each candidate word, the model has a probability; a genuine random number decides which word "wins" (roughly — higher-probability words win more often, by design).

Keyed-Gumbel sampling: the "random" number for each candidate word isn't random at all — it's `u = PRF(Hash(key, last H tokens), candidate_word)`, a pseudo-random function of the key and context. The word that maximizes `probability^(1/u)` (the Gumbel-max trick, mathematically equivalent to the "EXP" scheme) is chosen. Because the underlying `u` values are genuinely well-distributed (they just *look* random to anyone without the key), the output text reads completely naturally — same quality, same overall word-frequency distribution as honest sampling.

The fingerprint: someone with the key can recompute every `u` value that *must have applied* to the words actually chosen, using exactly the formula above. Define `S = sum(-log(1 - u_t))` over the counted positions. Under the null hypothesis (this text wasn't generated with this key), `S` follows a known distribution (Gamma), so there's an exact p-value for "how surprising is this specific S." Watermarked text — where the chosen words were *selected because* their `u` values were favorable — produces a small `S` (equivalently, a tiny p-value) far out in the tail.

This repo ships a real, runnable, stdlib-only implementation of that detector — no external engine, no GPU, no model:

```bash
python3 service/scripts/detect_gumbel.py your_text.txt --key 0xYOURKEY --json
```

Run against ordinary, non-watermarked prose it correctly finds nothing — here's real output from this repo, right now, against one plain sentence and an arbitrary key:

```json
{
  "tokens_total": 24, "counted": 20,
  "statistic": 19.9, "p_value": 0.479,
  "is_watermarked": false
}
```

`p_value: 0.479` means "this pattern is unremarkable — about a 48% chance of seeing a statistic this extreme from ordinary text." Real watermarked text under the *matching* key produces p-values many, many orders of magnitude smaller (the detector's default `--threshold` is `1e-6`). Note what this demo can't show: producing a genuine *positive* example requires the actual keyed sampler at generation time (the `arbi-serve` engine, not bundled here) — which is the point. You can't fake this pattern after the fact; it only exists if it was baked in during generation with the same key.

## Why this survives file cleaning, and what actually clears it

Both mechanisms live **entirely in which words got picked** — there is no header, no invisible character, no EXIF tag. That's why:

- Layer A (Unicode/metadata scrub) does **nothing** against it — there's nothing unicode or metadata-shaped to find.
- A light copy-edit (fix a typo, reorder two clauses) barely moves the statistic — the overwhelming majority of word choices are untouched, so the green-rate or Gumbel-`S` signal is still almost entirely intact.
- A **substantial** rewrite (different sentence structure, different synonyms, ideally a different, non-origin model doing the rewriting) replaces enough of the actual word-choice decisions that the statistical signal regresses toward chance. This is Layer B, and it's why the README is upfront that Layer B costs you the original prose — regressing the statistic *requires* changing enough words that "mostly the same text with a light touch-up" was never going to be an option.

## Try it yourself

```bash
# Keyed-Gumbel: real, stdlib-only, runs right now
python3 service/scripts/detect_gumbel.py your_text.txt --key 0x... --json

# KGW green-list: needs the optional MarkLLM checkout (setup_markllm.sh),
# but lets you generate a real watermarked sample under a config you pick,
# then detect it — so you can watch the green-rate statistic on genuine
# watermarked vs. plain text side by side.
python3 service/scripts/detect_text_watermark.py watermark prompt.txt --scheme kgw -o wm.txt -o2 plain.txt
python3 service/scripts/detect_text_watermark.py detect wm.txt --scheme kgw --json
python3 service/scripts/detect_text_watermark.py detect plain.txt --scheme kgw --json
```

Both are **same-key/same-config replay tools** — real, working detectors, but only against a key/config you (or a self-hosted engine you control) actually know. Neither cracks Claude's, Gemini's, or OpenAI's production keys; no public tool can. That's the honest boundary the README and `ethics.md` keep repeating, and now you know exactly *why* it's a hard boundary: without the key, the "green list" or the `u` values are just uniform noise to you too — the whole scheme's security is that the split is unrecoverable without it.
