"""Command line: `patchowner replay inventory.csv` and `patchowner serve`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import run_replay
from .inventory import InventoryError
from .report import BANNER
from .ssvc import Policy, PolicyError
from .state import StateStore


def _replay(args: argparse.Namespace) -> int:
    path = Path(args.inventory)
    try:
        policy = Policy.load(args.policy) if args.policy else None
        r = run_replay(path.read_text(), inventory_name=path.name, days=args.days, fallback_email=args.fallback,
                       budget=args.budget, refresh=args.refresh, policy=policy, state=StateStore(args.state))
    except InventoryError as e:
        print(f"Inventory problem: {e}", file=sys.stderr)
        return 2
    except PolicyError as e:
        print(f"Policy problem: {e}", file=sys.stderr)
        return 2
    s = r.summary
    print(f"KEV catalog {s.catalog_version}: {s.advisories_in_window} advisories in the last {s.days} days; policy: {s.policy_name}")
    print(f"{s.relevant_advisories} touched your {s.assets} assets; {s.sent} notices, {s.suppressed} suppressed, {s.unowned} without an owner")
    for u, n in s.by_urgency.items():
        print(f"  {u:<12}{n}")
    print("state: " + ", ".join(f"{k} {v}" for k, v in s.by_state.items()))
    for d in r.decisions:
        if d.sent:
            print(f"- [{d.urgency}] {d.match.advisory.cve_id} -> {d.match.asset.asset} -> {d.recipient_email} ({d.match.tier}; {d.vector or 'no path'})")
    for w in s.warnings:
        print(f"! {w}")
    for e, n in s.over_budget.items():
        print(f"! {e} would get {n} urgent notices; consider a digest")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(r.html)
    print(f"Report written to {out}")
    print(f"Note: {BANNER}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .web import app, configure

    configure(args.state)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="patchowner", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("replay", help="replay the KEV catalog against an inventory CSV and write an HTML report")
    r.add_argument("inventory")
    r.add_argument("--days", type=int, default=90)
    r.add_argument("--fallback", default="security@example.com", help="recipient for assets with no owner")
    r.add_argument("--budget", type=int, default=10, help="urgent notices per recipient before a digest is suggested")
    r.add_argument("--out", default="out/report.html")
    r.add_argument("--refresh", action="store_true", help="re-download the KEV feed")
    r.add_argument("--policy", help="SSVC deployer policy CSV (default: the SEI example tree)")
    r.add_argument("--state", default="out/state.json", help="where what people did about notices is kept")
    r.set_defaults(fn=_replay)

    s = sub.add_parser("serve", help="run the upload-a-CSV web demo")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--state", default="out/state.json")
    s.set_defaults(fn=_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
