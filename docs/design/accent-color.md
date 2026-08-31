# Accent color — rationale and contrast math

Decided 2026-08-31, superseding the Tailwind `blue-700`/`blue-400` defaults that
shipped with the original scaffold. Full context: `docs/legal-panel/../` aesthetic
audit found the accent was an unmodified starter color with no brand
differentiation, and a live probe found the dark-mode value additionally failed
WCAG contrast as a filled-button color (`bg-accent text-white` in dark mode
computed to 2.5:1 — below the 4.5:1 AA threshold for normal text).

## Values

| Mode  | Hex       | Role |
|-------|-----------|------|
| Light | `#233876` | ink navy — `--accent` |
| Dark  | `#5570c4` | lifted tint of the same hue — `--accent` |

Both are custom, off the Tailwind default ramp — chosen for a distinct,
institutional "counsel" register rather than generic SaaS blue, consistent with
`counselclear-strategy.md` framing the product as evidentiary/custody
infrastructure, not a consumer utility.

## Contrast (WCAG 2.1, relative luminance)

`--accent` does triple duty in this codebase: filled-button background with
white label text (`bg-accent text-white`), standalone link/text color
(`text-accent`), and border/focus-ring color (`border-accent`, `ring-accent`).
Those roles pull in opposite directions on a single hue — brute-force search
across the hue confirmed no value on this hue clears 4.5:1 against *both* pure
white and near-black background simultaneously, so the dark-mode value
prioritizes the CTA (fill) case over the secondary (link) case:

| | vs. white (fill + white text) | vs. dark bg `#09090b` (link/border) |
|---|---|---|
| Light `#233876` | 11.06:1 (AAA) | n/a — light mode bg is white |
| Dark `#5570c4` | 4.91:1 (AA) | 4.05:1 (just under AA's 4.5:1 for text; clears the 3:1 non-text/border threshold with room) |
| *Previous* dark `#60a5fa` | 2.54:1 (fails AA) | 7.83:1 |

The previous dark value looked fine as text/borders and was actively broken as
a button fill. The new value trades some of that link-text headroom to fix the
fill failure, since primary CTAs (login, release, matter actions) are the
higher-stakes surface. Dark-mode link text is not at formal AA (4.05 vs. 4.5)
but is a large improvement over shipping a failing button.

## If this needs revisiting

If a future pass wants full AA on dark-mode link text too, the fix is a second
token (e.g. `--accent-fill` distinct from `--accent`) so the two roles can
diverge — not in scope here to keep the token surface and diff minimal.
