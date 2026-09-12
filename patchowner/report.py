"""Render the replay result as a single HTML page: notices tab and policy-tree tab."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .health import Health
from .decide import ACT_NOW, DELIVERY, OUTCOME_TO_URGENCY, PLAN_UPDATE, UPDATE_SOON, WATCH, WHEN_TEXT, Decision, Summary
from .ssvc import AUTOMATABLE, EXPOSURE, HUMAN_IMPACT, OUTCOME_WORDS, OUTCOMES, POINTS, Policy, plain_policy

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)
SITEWIDE = ("This site is for educational and testing purposes only. Recommendations shown here are not professional security advice. "
            "For vulnerabilities on the CISA KEV catalog, the default action is immediate patching per CISA guidance. "
            "Always verify against vendor advisories and consult your security team before deferring any update.")
BANNER = ("Demo for testing the prioritization logic only. Not security advice. Every vulnerability here is actively exploited, "
          "and CISA's guidance is to patch immediately.")
SLOW = {"defer": "Defer", "scheduled": "Plan update"}   # answers that slow-walk an exploited vulnerability; each carries a caution


def caution(word: str) -> str:
    return (f"Simulated recommendation: {word}, for testing the prioritization logic only. This vulnerability is actively exploited "
            f"(CISA KEV). \u201c{word}\u201d here does not reflect CISA or vendor guidance. In a real environment, apply the patch immediately.")


KLASS = {ACT_NOW: "now", UPDATE_SOON: "soon", PLAN_UPDATE: "plan", WATCH: "watch", "Defer": "defer"}
OUTCOME_KLASS = {"immediate": "now", "out-of-cycle": "soon", "scheduled": "plan", "defer": "defer"}


def build_tree(policy: Policy, decisions: list[Decision]) -> list[dict]:
    """The active-exploitation subtree: exposure -> automatable -> human impact -> leaf, with notice counts."""
    by_leaf: dict[tuple[str, ...], list[Decision]] = defaultdict(list)
    for d in decisions:
        if d.assessment:
            by_leaf[d.assessment.values].append(d)
    tree = []
    for ex in reversed(EXPOSURE.values):  # internet first: the branch a busy person cares about
        ex_node = {"value": ex, "count": 0, "children": []}
        for auto in AUTOMATABLE.values:
            auto_node = {"value": auto, "count": 0, "children": []}
            for hi in HUMAN_IMPACT.values:
                values = ("active", ex, auto, hi)
                outcome, row = policy.outcome_for(values)
                leaf_decisions = by_leaf.get(values, [])
                auto_node["children"].append({
                    "value": hi, "key": "|".join(values), "row": row, "outcome": outcome,
                    "count": len(leaf_decisions), "notices": leaf_decisions,
                })
                auto_node["count"] += len(leaf_decisions)
            ex_node["children"].append(auto_node)
            ex_node["count"] += auto_node["count"]
        tree.append(ex_node)
    return tree


def _client_data(policy: Policy, decisions: list[Decision], share: str) -> str:
    """What the page needs to relabel a leaf and recompute counts without a server."""
    notices = [
        {"id": i, "key": d.key, "leaf": d.leaf_key, "altLeaf": d.alt_leaf_key, "question": bool(d.questions), "sent": d.sent,
         "cve": d.match.advisory.cve_id, "asset": d.match.asset.asset, "to": d.recipient_email,
         "state": {"action": d.state.action, "by": d.state.by, "note": d.state.note, "sentence": d.state.sentence} if d.state else None}
        for i, d in enumerate(decisions)
    ]
    rows = [{"row": row, "values": list(values), "outcome": outcome} for values, (outcome, row) in policy.rows.items()]
    return json.dumps({
        "notices": notices, "rows": rows, "header": policy.header,
        "share": share, "slow": SLOW, "cautions": {o: caution(w) for o, w in SLOW.items()},
        "words": OUTCOME_TO_URGENCY, "klass": OUTCOME_KLASS, "outcomes": list(OUTCOMES),
        "delivery": {o: {"ack": dl.acknowledge_within, "plan": dl.plan_within, "esc": dl.escalate_after, "oncall": dl.notify_oncall} for o, dl in DELIVERY.items()},
        "points": [{"name": pt.name, "question": pt.question, "values": list(pt.values), "plain": pt.plain, "clause": pt.clause} for pt in POINTS],
    })


def share_text(s: Summary, health: Health, inventory_name: str) -> str:
    """The plain-text summary the Share button copies: what a person would paste into a chat."""
    urgent = s.by_urgency.get(ACT_NOW, 0)
    return (f"PatchOwner replay: KEV catalog {s.catalog_version}, last {s.days} days, against {inventory_name} ({s.assets} assets). "
            f"{s.advisories_in_window} advisories published, {s.relevant_advisories} touched something we own, "
            f"{s.sent} notices sent ({urgent} Act now), {s.suppressed} suppressed with a reason. "
            f"Health: {health.word}" + (f", {health.issues} thing{'s' if health.issues != 1 else ''} to fix." if health.issues else ".")
            + " Demo only, not security advice.")


def render_html(summary: Summary, decisions: list[Decision], policy: Policy, health: Health, *, inventory_name: str) -> str:
    tpl = _env.get_template("report.html")
    return tpl.render(
        s=summary, inventory_name=inventory_name, policy=policy, health=health,
        decisions=decisions,
        sent=[d for d in decisions if d.sent],
        suppressed=[d for d in decisions if not d.sent],
        when_text=WHEN_TEXT, klass=KLASS, outcome_klass=OUTCOME_KLASS, outcomes=OUTCOMES, points=POINTS,
        urgencies=[ACT_NOW, UPDATE_SOON, PLAN_UPDATE, WATCH],
        tree=build_tree(policy, decisions),
        plain_lines=plain_policy(policy),
        delivery=DELIVERY,
        outcome_words=OUTCOME_WORDS,
        sitewide=SITEWIDE, banner=BANNER, slow=SLOW, caution=caution,
        client_data=_client_data(policy, decisions, share_text(summary, health, inventory_name)),
    )
