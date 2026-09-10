"""One call that runs the whole replay: feed -> window -> match -> decide -> summarize -> html."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .decide import Decision, Summary, decide, summarize
from .inventory import parse_inventory
from .kev import in_window, load_feed
from .matching import match_all
from .report import render_html
from .ssvc import Policy
from .state import StateStore


@dataclass
class Replay:
    summary: Summary
    decisions: list[Decision]
    html: str


def run_replay(csv_text: str, *, inventory_name: str, days: int = 90, fallback_email: str = "security@example.com",
               fallback_name: str = "Security team", budget: int = 10, refresh: bool = False,
               today: date | None = None, policy: Policy | None = None, state: StateStore | None = None) -> Replay:
    assets = parse_inventory(csv_text)
    warnings = [f"Row {a.row} ({a.asset or 'blank'}): {w}" for a in assets for w in a.warnings]
    advisories, version = load_feed(refresh=refresh)
    window = in_window(advisories, days, today)
    matches = match_all(window, assets)
    policy = policy or Policy.default()
    decisions = decide(matches, fallback_email, fallback_name, today, policy, state)
    summary = summarize(decisions, days=days, catalog_version=version, policy_name=policy.name, advisories_in_window=len(window),
                        assets=len(assets), budget=budget, warnings=warnings)
    return Replay(summary, decisions, render_html(summary, decisions, policy, inventory_name=inventory_name))
