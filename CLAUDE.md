# PatchOwner Operating Contract &amp; Context Router

## Tech Stack
- Python 3.12, `uv` package manager, FastAPI REST microservices
- PostgreSQL with SQLAlchemy ORM &amp; Alembic migrations 
- Multi-tenant architecture with Row-Level Security (`tenant_id` foreign keys)
- Carnegie Mellon SSVC 2.0 decision engine &amp; CISA KEV continuous sync 

## Core Commands
- Environment Setup: `uv sync` 
- Dev Server: `uv run uvicorn patchowner.web:app --reload`
- Test Suite: `uv run pytest` 
- Lint &amp; Format: `uv run ruff check --fix && uv run ruff format`
- Type Check: `uv run mypy patchowner`
- DB Migrations: `uv run alembic upgrade head` 

## Non-Negotiable Constraints
1. **Tenant Isolation**: Every SQL model and query must strictly scope to `tenant_id` 
2. **SSVC Reason Integrity**: Preserve Carnegie Mellon SSVC 2.0 tree outcomes and 1-sentence plain-English reasons 
3. **Plan First**: Draft implementation blueprints before editing core engines (`engine.py`, `web.py`, `db/`) 
4. **Evidence-Based Done**: Verify all code changes via `uv run pytest` before turn completion 

## Pointers & Extension Routing
- DB Isolation Rules: `.claude/rules/db.md` (lazy-loaded for `patchowner/db/**/*.py`) 
- SSVC Tree Rules: `.claude/rules/ssvc.md` (lazy-loaded for `patchowner/engine.py`, `ssvc.py`)
- Security Auditor Subagent: `.claude/agents/security-auditor.md`
