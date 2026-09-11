"""Health: can PatchSignal actually route a notice for every asset, and is anyone acting on what was sent?

Every check is a plain sentence, a count, and the one thing to do about it. Nothing here changes a decision;
it tells the person running the replay where the inventory or the follow-through is thin.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

from .decide import ACT_NOW, UPDATE_SOON, Decision, Summary
from .inventory import Asset

GOOD, WARN, BAD = "good", "warn", "bad"
GRADE_WORDS = {GOOD: "Ready", WARN: "Mostly ready", BAD: "Needs attention"}
FEED_STALE_AFTER = 7      # days: KEV is updated most working days
EXCEPTION_SOON = 30       # days: an exception ending this soon is worth a look now


@dataclass
class Check:
    label: str                 # what good looks like: "Every active asset has an owner"
    ok: int                    # how many pass
    total: int                 # out of how many
    status: str                # good | warn | bad
    detail: str                # the failing ones, by name, or a reassuring sentence
    fix: str = ""              # the one thing to do; blank when nothing is needed
    names: list[str] = field(default_factory=list)


@dataclass
class Health:
    grade: str                 # good | warn | bad
    headline: str              # one sentence for the top of the tab
    checks: list[Check]
    feed_date: date | None
    feed_age_days: int | None
    active_assets: int
    handled: int               # fixed or does-not-apply
    unhandled_urgent: int      # Act now or Update soon with nobody acting

    @property
    def word(self) -> str:
        return GRADE_WORDS[self.grade]

    @property
    def issues(self) -> int:
        return sum(1 for c in self.checks if c.status != GOOD)


def _names(assets: list[Asset], limit: int = 6) -> str:
    names = [a.asset or f"row {a.row}" for a in assets]
    if len(names) <= limit:
        return ", ".join(names)
    return ", ".join(names[:limit]) + f" and {len(names) - limit} more"


def _coverage(label: str, assets: list[Asset], missing: list[Asset], fix: str, *, bad_below: float = 0.8) -> Check:
    total, ok = len(assets), len(assets) - len(missing)
    if not missing:
        status, detail, fix = GOOD, "All of them.", ""
    else:
        status = BAD if total and ok / total < bad_below else WARN
        detail = f"Missing on {_names(missing)}."
    return Check(label, ok, total, status, detail, fix, [a.asset for a in missing])


def feed_date_from_version(catalog_version: str) -> date | None:
    """CISA's catalogVersion is YYYY.MM.DD. Anything else is treated as unknown."""
    try:
        y, m, d = (int(x) for x in catalog_version.split("."))
        return date(y, m, d)
    except (ValueError, AttributeError):
        return None


def assess_health(assets: list[Asset], decisions: list[Decision], summary: Summary, *, today: date | None = None) -> Health:
    today = today or date.today()
    active = [a for a in assets if a.status != "retired"]
    retired = [a for a in assets if a.status == "retired"]
    checks: list[Check] = []

    # 1. Routing: is there a person for each role? Without these the notice goes to the fallback or nowhere.
    checks.append(_coverage("Every active asset has an owner to fix it", active, [a for a in active if not a.has_owner],
                            "Add owner_email (and owner_name) to those rows. Until then the fallback contact gets their notices."))
    checks.append(_coverage("Every active asset has an accountable person", active, [a for a in active if not a.accountable],
                            "Add accountable. They get one status line per asset, never the technical detail.", bad_below=0.5))
    exposed = [a for a in active if a.internet_exposed or a.exposure == "open"]
    checks.append(_coverage("Every internet-facing asset has an on-call contact", exposed, [a for a in exposed if not a.oncall],
                            "Add oncall. On Act now, they join the owner; nobody else does.", bad_below=0.5))
    checks.append(_coverage("Every active asset has an escalation contact", active, [a for a in active if not a.escalate_to],
                            "Add escalate_to. They hear nothing unless the window passes.", bad_below=0.5))

    # 2. Data quality: things the parser had to guess or ignore.
    warned = [a for a in assets if a.warnings]
    checks.append(Check("Every row parsed cleanly", len(assets) - len(warned), len(assets),
                        GOOD if not warned else WARN,
                        "No warnings." if not warned else f"Warnings on {_names(warned)}. See the top of the Notices tab.",
                        "" if not warned else "Fix the flagged values; an ignored value falls back to a default that may be wrong.",
                        [a.asset for a in warned]))
    no_version = [a for a in active if not a.version]
    checks.append(Check("Versions recorded", len(active) - len(no_version), len(active),
                        GOOD if not no_version else WARN,
                        "All of them." if not no_version else f"No version on {_names(no_version)}.",
                        "" if no_version == [] else "Add version. KEV carries no version data, so PatchSignal never claims one is affected; the owner still needs it to check.",
                        [a.asset for a in no_version]))

    # 3. Exceptions: expired ones silently stop suppressing; ones ending soon deserve a look.
    expired = [a for a in active if a.exception_until and a.exception_until < today]
    ending = [a for a in active if a.exception_until and today <= a.exception_until <= today + timedelta(days=EXCEPTION_SOON)]
    if expired:
        checks.append(Check("No exception has expired", 0, len(expired), BAD,
                            f"Expired on {_names(expired)}. Their notices are being sent again.",
                            "Extend exception_until with a fresh reason, or remove the row's exception and fix the asset.",
                            [a.asset for a in expired]))
    if ending:
        checks.append(Check(f"No exception ends within {EXCEPTION_SOON} days", 0, len(ending), WARN,
                            f"Ending soon on {_names(ending)}.",
                            "Decide now whether to extend or to fix; the notice resumes the day after.",
                            [a.asset for a in ending]))
    if not expired and not ending:
        on_file = [a for a in active if a.exception_until]
        checks.append(Check("Exceptions are current", len(on_file), len(on_file), GOOD,
                            "None on file." if not on_file else f"{len(on_file)} on file, none expired or ending within {EXCEPTION_SOON} days."))
    if retired:
        checks.append(Check("Retired assets stay quiet", len(retired), len(retired), GOOD,
                            f"{_names(retired)}: retired, so nothing is sent and each suppression is listed with its reason."))

    # 4. The feed: KEV is updated most working days.
    feed_date = feed_date_from_version(summary.catalog_version)
    age = (today - feed_date).days if feed_date else None
    if age is None:
        checks.append(Check("KEV catalog is fresh", 0, 1, WARN, f"Catalog version '{summary.catalog_version}' has no date in it.",
                            "Run with --refresh to download the feed again."))
    elif age > FEED_STALE_AFTER:
        checks.append(Check("KEV catalog is fresh", 0, 1, BAD, f"The cached catalog is {age} days old (version {summary.catalog_version}).",
                            "Run with --refresh. Anything CISA added since is missing from this replay."))
    else:
        checks.append(Check("KEV catalog is fresh", 1, 1, GOOD, f"Version {summary.catalog_version}, {age} day{'s' if age != 1 else ''} old."))

    # 5. Follow-through: was anything sent, and is anyone acting on the urgent ones?
    sent = [d for d in decisions if d.sent]
    handled = sum(1 for d in sent if d.state and d.state.action in {"fixed", "not_applicable"})
    urgent = [d for d in sent if d.urgency in {ACT_NOW, UPDATE_SOON}]
    idle = [d for d in urgent if d.state is None or d.state.action == "reopened"]
    if urgent:
        checks.append(Check("Someone has acted on every urgent notice", len(urgent) - len(idle), len(urgent),
                            GOOD if not idle else (BAD if any(d.urgency == ACT_NOW for d in idle) else WARN),
                            "All of them." if not idle else "Nobody has touched " + ", ".join(f"{d.match.advisory.cve_id} on {d.match.asset.asset}" for d in idle[:4]) + (f" and {len(idle) - 4} more" if len(idle) > 4 else "") + ".",
                            "" if not idle else "Acknowledge is the first button on each card. Acknowledged is not fixed, but it is not silence."))
    else:
        checks.append(Check("Someone has acted on every urgent notice", 0, 0, GOOD, "Nothing urgent was sent in this window."))
    if summary.over_budget:
        who = ", ".join(f"{e} ({n})" for e, n in summary.over_budget.items())
        checks.append(Check("Nobody is over their notice budget", 0, len(summary.over_budget), WARN,
                            f"Over budget: {who}.", "Route lower-confidence items to a weekly digest, or split ownership."))
    else:
        checks.append(Check("Nobody is over their notice budget", 1, 1, GOOD, "Nobody would have been flooded."))

    grade = BAD if any(c.status == BAD for c in checks) else (WARN if any(c.status == WARN for c in checks) else GOOD)
    issues = sum(1 for c in checks if c.status != GOOD)
    if grade == GOOD:
        headline = f"Every one of your {len(active)} active assets can be routed, the catalog is current, and nothing urgent is sitting untouched."
    else:
        headline = f"{issues} thing{'s' if issues != 1 else ''} to fix, worst first. Each one says what to do."
    order = {BAD: 0, WARN: 1, GOOD: 2}
    checks.sort(key=lambda c: order[c.status])
    return Health(grade, headline, checks, feed_date, age, len(active), handled, len(idle))
