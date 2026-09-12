Static copy of the demo report, served at https://patchowner.com by Vercel. Every push to main deploys it.

Rebuild it with:

    uv run patchowner replay examples/inventory.csv --refresh && cp out/report.html site/index.html
