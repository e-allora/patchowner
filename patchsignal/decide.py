"""Turn matches into decisions: SSVC outcome, urgency words, recipient, escalation, suppression."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date

from .matching import Match
from .ssvc import AUTOMATABLE, Assessment, Policy, assess
from .state import HANDLED, Action, StateStore, notice_key

ACT_NOW, UPDATE_SOON, PLAN_UPDATE, WATCH, DEFER = "Act now", "Update soon", "Plan update", "Watch", "Defer"
URGENCY_ORDER = {ACT_NOW: 0, UPDATE_SOON: 1, PLAN_UPDATE: 2, WATCH: 3, DEFER: 4}
OUTCOME_TO_URGENCY = {"immediate": ACT_NOW, "out-of-cycle": UPDATE_SOON, "scheduled": PLAN_UPDATE, "defer": DEFER}
URGENCY_TO_OUTCOME = {v: k for k, v in OUTCOME_TO_URGENCY.items()}

WHEN_TEXT = {
    ACT_NOW: "Start mitigation today.",
    UPDATE_SOON: "Sooner than your normal cycle, at the next available opportunity, and no later than the CISA due date.",
    PLAN_UPDATE: "During regularly scheduled maintenance.",
    WATCH: "No action yet. Tell us whether this product is really in use.",
    DEFER: "No action at present.",
}


@dataclass(frozen=True)
class Delivery:
    """What an outcome means for people. This is the THEN half of a policy, and it lives on the leaf."""
    notify_oncall: bool
    acknowledge_within: str
    plan_within: str
    escalate_after: str
    digest_allowed: bool


DELIVERY: dict[str, Delivery] = {
    "immediate": Delivery(True, "2 hours", "8 hours", "24 hours", False),
    "out-of-cycle": Delivery(False, "2 days", "7 days", "7 days", False),
    "scheduled": Delivery(False, "7 days", "30 days", "30 days", True),
    "defer": Delivery(False, "", "", "", True),
}
WATCH_DELIVERY = Delivery(False, "7 days", "", "", True)


@dataclass(frozen=True)
class Recipient:
    email: str
    name: str
    role: str  # fixer | on-call | accountable | escalation


def _person(email: str, name: str = "") -> tuple[str, str]:
    if name:
        return email, name
    local = email.split("@")[0]
    return email, (local.upper() if len(local) <= 4 and "." not in local else local.replace(".", " ").title())


@dataclass
class Decision:
    match: Match
    urgency: str
    urgency_reason: str
    recipient_email: str
    recipient_name: str
    recipient_is_fallback: bool
    assessment: Assessment | None = None   # None for "possible" matches: no path until a human confirms
    outcome: str | None = None
    policy_row: int | None = None
    vector: str = ""
    fixers: list[Recipient] = field(default_factory=list)      # get the full card
    accountable: Recipient | None = None                       # gets one status line
    escalation: Recipient | None = None                        # hears only if unresolved
    delivery: Delivery = WATCH_DELIVERY
    state: Action | None = None                # what a person last did about it
    history: list[Action] = field(default_factory=list)
    suppressed_reason: str | None = None
    facts: list[str] = field(default_factory=list)
    estimates: list[str] = field(default_factory=list)

    @property
    def sent(self) -> bool:
        return self.suppressed_reason is None

    @property
    def key(self) -> str:
        return notice_key(self.match.advisory.cve_id, self.match.asset.asset)

    @property
    def handled(self) -> bool:
        return bool(self.state and self.state.action in HANDLED)

    @property
    def cc(self) -> list[str]:
        return [r.email for r in self.fixers[1:]]

    @property
    def escalate_to(self) -> str:
        return self.escalation.email if self.escalation else ""

    @property
    def escalate_after(self) -> str:
        return self.delivery.escalate_after

    @property
    def status_line(self) -> str:
        """The accountable person's whole view of this notice. No CVE, no description."""
        a = self.match.asset
        who = self.fixers[0].name if self.fixers else "nobody yet"
        if self.urgency == WATCH:
            return f"{a.asset}: we are checking whether an exploited vulnerability applies. {who} has been asked."
        if self.state and self.state.action == "fixed":
            return f"{a.asset}: fixed. {self.state.sentence} Nothing needed from you."
        if self.state and self.state.action == "assigned":
            who = self.state.note or who
        need = f"Acknowledge within {self.delivery.acknowledge_within}" if self.delivery.acknowledge_within else "No deadline"
        plan = f", plan within {self.delivery.plan_within}" if self.delivery.plan_within else ""
        if self.state and self.state.action == "acknowledged":
            return f"{a.asset}: {self.urgency.lower()}. {who} has acknowledged it. Plan due within {self.delivery.plan_within or 'the normal cycle'}. Decision needed from you: none at this time."
        return f"{a.asset}: {self.urgency.lower()}. Assigned to {who}. {need}{plan}. Decision needed from you: none at this time."

    @property
    def leaf_key(self) -> str:
        return self.assessment.leaf_key if self.assessment else ""

    @property
    def alt_leaf_key(self) -> str:
        """Where this notice would land if a person confirms the attack needs help."""
        return self.assessment.with_value(AUTOMATABLE, "no").leaf_key if self.assessment else ""

    @property
    def questions(self) -> list[str]:
        return self.assessment.questions if self.assessment else []

    @property
    def plain_reason(self) -> str:
        """One sentence a busy person can read: the urgency and the three reasons."""
        if not self.assessment:
            return f"{self.urgency}, because we are not sure this product is the one on this asset."
        return f"{self.urgency}, because {self.assessment.because()}."

    @property
    def path_text(self) -> str:
        if not self.assessment:
            return "match is only possible; no policy path until the owner confirms the product"
        return " › ".join(f"{s.point.name}: {s.value}" for s in self.assessment.steps) + f" → {self.outcome}"

    @property
    def headline(self) -> str:
        a = self.match.asset
        return f"Does this apply? {a.asset}" if self.urgency == WATCH else f"Action needed: update {a.asset}"

    @property
    def what_to_do(self) -> str:
        if self.urgency == WATCH:
            return "Tell us whether this product is really in use. If it is, follow the vendor fix."
        text = self.match.advisory.required_action or "Apply the vendor's update."
        first = text.split(". ")[0]
        # CISA's boilerplate continues with ", ensuring compliance with BOD ..."; the action is before the comma.
        first = first.split(", ensuring compliance")[0].split(", per ")[0]
        return first.rstrip(".") + "."

    @property
    def why_it_matters(self) -> str:
        first = self.match.advisory.description.split(". ")[0].rstrip(".")
        return (first[:220] + "…") if len(first) > 220 else first + "."


def _suppression(m: Match, today: date) -> str | None:
    a = m.asset
    owner = a.owner_name or a.team or "none recorded"
    if a.status in {"retired", "decommissioned", "disposed"}:
        return f"asset is marked '{a.status}' (row {a.row}). Owner: {owner}."
    if a.exception_until and a.exception_until >= today:
        return f"exception on file until {a.exception_until.isoformat()} ({a.exception_reason or 'accepted risk'}). Owner: {owner}."
    return None


def decide(matches: list[Match], fallback_email: str, fallback_name: str = "Security team",
           today: date | None = None, policy: Policy | None = None, state: StateStore | None = None) -> list[Decision]:
    today = today or date.today()
    policy = policy or Policy.default()
    state = state or StateStore(None)
    out: list[Decision] = []
    for m in matches:
        a, adv = m.asset, m.advisory
        if a.has_owner:
            email, name, fb = a.owner_email, a.owner_name or a.owner_email, False
        else:
            email, name, fb = fallback_email, fallback_name, True

        d = Decision(match=m, urgency=WATCH, urgency_reason="", recipient_email=email, recipient_name=name,
                     recipient_is_fallback=fb, suppressed_reason=_suppression(m, today))
        if m.tier == "possible":
            d.urgency_reason = f"match is only possible: {m.reason}"
        else:
            d.assessment = assess(adv, a)
            o = policy.evaluate(d.assessment)
            d.outcome, d.policy_row, d.vector = o.priority, o.row, d.assessment.vector()
            d.urgency = OUTCOME_TO_URGENCY[o.priority]
            d.urgency_reason = f"{policy.name}, row {o.row}: {d.path_text}"
            if o.priority == "defer" and d.suppressed_reason is None:
                d.suppressed_reason = f"the policy ({policy.name}, row {o.row}) says defer for this path: {d.path_text}. Owner: {name}."

        d.delivery = DELIVERY[d.outcome] if d.outcome else WATCH_DELIVERY
        d.fixers = [Recipient(email, name, "fixer")]
        if d.delivery.notify_oncall:
            oncall_email, oncall_name = _person(a.oncall or fallback_email, "" if a.oncall else fallback_name)
            if oncall_email != email:
                d.fixers.append(Recipient(oncall_email, oncall_name, "on-call"))
        if a.accountable and d.urgency != WATCH:
            d.accountable = Recipient(*_person(a.accountable), "accountable")
        esc = a.escalate_to or (fallback_email if not fb else "")
        if esc and d.delivery.escalate_after and esc != email:
            d.escalation = Recipient(*_person(esc, fallback_name if esc == fallback_email else ""), "escalation")

        d.state, d.history = state.current(d.key), state.history(d.key)
        if d.state and d.state.action == "not_applicable" and d.suppressed_reason is None:
            d.suppressed_reason = f"{d.state.sentence} Recorded {d.state.at[:10]}. Reopen it if that changes. Owner: {name}."

        d.facts.append(f"CISA confirms {adv.cve_id} is exploited in the wild (added {adv.date_added.isoformat()}).")
        if adv.ransomware_known:
            d.facts.append("CISA reports use in ransomware campaigns.")
        if adv.due_date:
            d.facts.append(f"Federal remediation due date: {adv.due_date.isoformat()}.")
        d.estimates.append(f"Product match is {m.tier}: {m.reason}.")
        d.estimates.append(
            f"Version {a.version} was not checked; the CISA feed does not list affected versions." if a.version
            else "No version recorded for this asset, so affected-version status is unknown."
        )
        if fb:
            d.estimates.append("No owner recorded for this asset; routed to the fallback contact.")
        out.append(d)
    out.sort(key=lambda d: (URGENCY_ORDER[d.urgency], d.match.advisory.date_added))
    return out


@dataclass
class Summary:
    days: int
    catalog_version: str
    policy_name: str
    advisories_in_window: int
    assets: int
    relevant_advisories: int
    sent: int
    suppressed: int
    unowned: int
    by_urgency: dict[str, int]
    by_recipient: dict[str, list[Decision]]
    by_person: dict[str, dict]           # email -> {name, fixer, status, escalation}
    status_lines: dict[str, list[Decision]]  # accountable email -> notices
    by_state: dict[str, int]                 # open | acknowledged | assigned | fixed
    over_budget: dict[str, int]
    warnings: list[str]


def summarize(decisions: list[Decision], *, days: int, catalog_version: str, policy_name: str, advisories_in_window: int,
              assets: int, budget: int, warnings: list[str]) -> Summary:
    sent = [d for d in decisions if d.sent]
    by_rec: dict[str, list[Decision]] = defaultdict(list)
    for d in sent:
        by_rec[d.recipient_email].append(d)
    urgent = Counter(d.recipient_email for d in sent if d.urgency in {ACT_NOW, UPDATE_SOON})
    people: dict[str, dict] = {}

    def bump(r: Recipient, col: str) -> None:
        row = people.setdefault(r.email, {"name": r.name, "fixer": 0, "status": 0, "escalation": 0})
        row[col] += 1

    status_lines: dict[str, list[Decision]] = defaultdict(list)
    seen_assets: set[tuple[str, str]] = set()
    for d in sent:  # sorted most urgent first, so the first notice per asset is the one the status line reports
        for r in d.fixers:
            bump(r, "fixer")
        if d.accountable:
            key = (d.accountable.email, d.match.asset.asset)
            if key not in seen_assets:
                seen_assets.add(key)
                bump(d.accountable, "status")
                status_lines[d.accountable.email].append(d)
        if d.escalation:
            bump(d.escalation, "escalation")
    return Summary(
        days=days, catalog_version=catalog_version, policy_name=policy_name, advisories_in_window=advisories_in_window,
        assets=assets, relevant_advisories=len({d.match.advisory.cve_id for d in decisions}),
        sent=len(sent), suppressed=len(decisions) - len(sent),
        unowned=sum(1 for d in sent if d.recipient_is_fallback),
        by_urgency={u: sum(1 for d in sent if d.urgency == u) for u in (ACT_NOW, UPDATE_SOON, PLAN_UPDATE, WATCH)},
        by_recipient=dict(sorted(by_rec.items(), key=lambda kv: -len(kv[1]))),
        by_person=dict(sorted(people.items(), key=lambda kv: -(kv[1]["fixer"] * 3 + kv[1]["status"] + kv[1]["escalation"]))),
        status_lines=dict(status_lines),
        by_state={
            "open": sum(1 for d in sent if d.state is None),
            "acknowledged": sum(1 for d in sent if d.state and d.state.action == "acknowledged"),
            "assigned": sum(1 for d in sent if d.state and d.state.action == "assigned"),
            "fixed": sum(1 for d in sent if d.state and d.state.action == "fixed"),
        },
        over_budget={e: n for e, n in urgent.items() if n > budget},
        warnings=warnings,
    )
