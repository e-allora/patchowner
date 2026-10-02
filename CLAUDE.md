# PatchOwner: operating contract for Claude

PatchOwner is a local proof of concept. It replays the CISA Known Exploited Vulnerabilities (KEV) catalog
against an inventory CSV and writes one HTML report that says which notices would have gone to whom, which
stayed quiet, and why. The decision is the SEI/CERT SSVC 2.0 deployer tree. Read `README.md` first; it is
kept true to the code and the site.

## What actually exists

- Python 3.12 (pinned in `.python-version`; 3.13 also works), `uv` for everything.
- Pure-Python engine: `kev.py` (feed download and cache), `inventory.py` (CSV), `matching.py` (rapidfuzz),
  `ssvc.py` (decision points, policy CSV), `decide.py` (routing, suppression, budget), `health.py`,
  `state.py` (what people did, a JSON file), `report.py` + `templates/report.html` (Jinja2), `engine.py`.
- Two entry points: `patchowner replay` (CLI, writes `out/report.html`) and `patchowner serve`
  (FastAPI: `/` upload form, `/replay`, `/act`). Local only. No accounts, no database, no email, no tickets.
- `site/index.html` is a **build artifact**: the rendered report for `examples/inventory.csv`, served at
  https://patchowner.com by Vercel on every push to `main`. Rebuild it; do not hand-edit it
  (`site/README.md` has the command).
- `docs/design/db/` is a schema sketch for a possible hosted multi-tenant version. It is not wired in and its
  dependencies are not installed. Do not import it or describe it as part of the product.

## Commands

```
uv sync                                                 # environment
uv run patchowner replay examples/inventory.csv         # writes out/report.html
uv run patchowner serve                                 # http://127.0.0.1:8000
uv run pytest                                           # the test suite; 4 tests skip until data/kev.json is cached
uv run ruff check --fix && uv run ruff format           # lint and format (config in pyproject.toml)
```

## Non-negotiable constraints

1. **Say only what is true.** Every claim in `README.md`, the About tab, and the landing copy must be
   checkable against the code or the data. Facts (CISA, the inventory) and estimates (matching, automatable)
   stay labeled separately. An estimate never lowers urgency on its own. No notice ever claims a version is
   affected: KEV carries no version data.
2. **Keep the disclaimers.** The sitewide notice, the banner, and the inline caution on Defer / Plan update
   exist because every KEV entry is actively exploited and CISA's guidance is to patch now. Do not soften,
   move, or hide them.
3. **SSVC integrity.** Decision-point vocabulary is the SEI/CERT one and is fixed. The default policy CSV is
   the SEI example tree, unchanged. Every notice keeps its one-sentence plain-English reason and its SSVC
   vector under "For the auditor".
4. **Plan first** before editing `decide.py`, `ssvc.py`, `engine.py`, `web.py`, or the report template:
   write down the intended behaviour change and which tests prove it, then edit.
5. **Evidence-based done.** `uv run pytest` and `uv run ruff check` pass before a turn ends. If the change
   touches the report, regenerate `site/index.html` from the template (needs network for the KEV feed) or say
   plainly that the live site still needs a rebuild.
6. **Nothing leaves the machine.** No telemetry, no outbound calls except the KEV download. The static site
   stores button state in the visitor's browser only.

## Planned, not built

Jira/ServiceNow, email and Slack delivery, overdue tracking, multi-tenant MSP views, KEV diffing, scanner
integrations, any AI-generated analysis, and the PostgreSQL schema in `docs/design/db/`. These wait for a
paying pilot. Describe them as future work, never as features.

## Pointers

- Hooks: `.claude/hooks/lint_changed.py` (ruff on edited Python files), `.claude/hooks/test_gate.py`
  (pytest must pass before a turn ends).
- Subagent: `.claude/agents/security-auditor.md` reviews the FastAPI surface and the report template for
  input handling and output escaping.
