# Database schema sketch (not wired in)

These two files are a **design sketch** for a possible future multi-tenant, hosted version of PatchOwner:
SQLAlchemy models for tenants, users, assets, advisories, policies, notices, and an action history, plus an
async session factory for PostgreSQL.

**Nothing in the running product uses them.** PatchOwner today is a local proof of concept: it reads a CSV,
replays the CISA KEV catalog, and writes one HTML file. What people did about a notice lives in a small JSON
file (`out/state.json`). There is no database, no accounts, and no hosted service. SQLAlchemy and asyncpg are
not project dependencies, so these files do not import in the project environment and are excluded from lint
and tests.

They are kept here so the direction is visible, not hidden. If and when a paying pilot asks for a hosted
multi-tenant version, this is the starting point, and the first non-negotiable rule for that work is that every
tenant-owned table carries an indexed `tenant_id` and every query is scoped by it.
