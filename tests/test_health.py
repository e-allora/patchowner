"""Health: routing coverage, exceptions, feed freshness, follow-through. No feed needed."""
from datetime import date, timedelta

from patchowner.decide import ACT_NOW, Delivery, Decision, Recipient, summarize
from patchowner.health import BAD, GOOD, WARN, assess_health, feed_date_from_version
from patchowner.inventory import parse_inventory
from patchowner.kev import Advisory
from patchowner.matching import Match
from patchowner.state import Action

TODAY = date(2026, 9, 11)
FULL = "asset,vendor,product,version,internet_exposed,owner_email,accountable,oncall,escalate_to,status,exception_until\n"


def _summary(decisions=(), catalog="2026.09.10", assets=1, warnings=(), budget=10):
    return summarize(list(decisions), days=90, catalog_version=catalog, policy_name="p", advisories_in_window=10,
                     assets=assets, budget=budget, warnings=list(warnings))


def _decision(asset, urgency=ACT_NOW, state=None):
    adv = Advisory(cve_id="CVE-2026-1", vendor="V", product="P", name="n", description="d", required_action="patch",
                   date_added=TODAY, due_date=None, ransomware_known=False)
    m = Match(advisory=adv, asset=asset, tier="exact", score=100, reason="")
    return Decision(match=m, urgency=urgency, urgency_reason="", recipient_email="o@x", recipient_name="O", recipient_is_fallback=False,
                    fixers=[Recipient("o@x", "O", "fixer")], delivery=Delivery(True, "2 hours", "8 hours", "24 hours", False), state=state)


def test_complete_inventory_is_ready():
    assets = parse_inventory(FULL + "A,V,P,1.0,yes,o@x,a@x,oc@x,e@x,active,\n")
    h = assess_health(assets, [], _summary(), today=TODAY)
    assert h.grade == GOOD and h.issues == 0
    assert "can be routed" in h.headline
    assert all(c.status == GOOD for c in h.checks)


def test_missing_owner_is_named_and_gets_a_fix():
    good = "".join(f"A{i},V,P,1.0,yes,o@x,a@x,oc@x,e@x,active,\n" for i in range(4))
    assets = parse_inventory(FULL + good + "Print server,V,P,1.0,no,,a@x,oc@x,e@x,active,\n")
    h = assess_health(assets, [], _summary(), today=TODAY)
    owner = next(c for c in h.checks if c.label.startswith("Every active asset has an owner"))
    assert owner.ok == 4 and owner.total == 5 and owner.status == WARN  # one in five is thin, not broken
    assert "Print server" in owner.detail and "owner_email" in owner.fix


def test_coverage_below_threshold_is_bad_and_checks_sort_worst_first():
    rows = "".join(f"A{i},V,P,1.0,no,,a@x,,e@x,active,\n" for i in range(5))
    h = assess_health(parse_inventory(FULL + rows), [], _summary(), today=TODAY)
    assert h.grade == BAD and h.word == "Needs attention"
    assert h.checks[0].status == BAD
    assert [c.status for c in h.checks] == sorted((c.status for c in h.checks), key={BAD: 0, WARN: 1, GOOD: 2}.get)


def test_retired_assets_do_not_count_against_coverage():
    assets = parse_inventory(FULL + "Old,V,P,1.0,no,,,,,retired,\nA,V,P,1.0,yes,o@x,a@x,oc@x,e@x,active,\n")
    h = assess_health(assets, [], _summary(), today=TODAY)
    assert h.grade == GOOD and h.active_assets == 1
    assert any("Retired assets stay quiet" == c.label and "Old" in c.detail for c in h.checks)


def test_oncall_only_matters_for_internet_facing():
    assets = parse_inventory(FULL + "Inside,V,P,1.0,no,o@x,a@x,,e@x,active,\n")
    h = assess_health(assets, [], _summary(), today=TODAY)
    oc = next(c for c in h.checks if "on-call" in c.label)
    assert oc.total == 0 and oc.status == GOOD


def test_expired_and_ending_exceptions():
    gone = (TODAY - timedelta(days=1)).isoformat()
    soon = (TODAY + timedelta(days=10)).isoformat()
    far = (TODAY + timedelta(days=200)).isoformat()
    assets = parse_inventory(FULL + f"X,V,P,1.0,no,o@x,a@x,oc@x,e@x,active,{gone}\nY,V,P,1.0,no,o@x,a@x,oc@x,e@x,active,{soon}\nZ,V,P,1.0,no,o@x,a@x,oc@x,e@x,active,{far}\n")
    h = assess_health(assets, [], _summary(), today=TODAY)
    labels = {c.label: c for c in h.checks}
    assert labels["No exception has expired"].status == BAD and "X" in labels["No exception has expired"].detail
    assert labels["No exception ends within 30 days"].status == WARN and "Y" in labels["No exception ends within 30 days"].detail
    assert "Exceptions are current" not in labels


def test_feed_freshness():
    assert feed_date_from_version("2026.09.10") == date(2026, 9, 10)
    assert feed_date_from_version("weird") is None
    assets = parse_inventory(FULL + "A,V,P,1.0,yes,o@x,a@x,oc@x,e@x,active,\n")
    fresh = assess_health(assets, [], _summary(catalog="2026.09.10"), today=TODAY)
    stale = assess_health(assets, [], _summary(catalog="2026.08.01"), today=TODAY)
    unknown = assess_health(assets, [], _summary(catalog="weird"), today=TODAY)
    assert fresh.feed_age_days == 1 and fresh.grade == GOOD
    assert stale.grade == BAD and "--refresh" in next(c.fix for c in stale.checks if c.label == "KEV catalog is fresh")
    assert unknown.feed_age_days is None and unknown.grade == WARN


def test_urgent_notices_nobody_touched_are_bad_until_acknowledged():
    assets = parse_inventory(FULL + "A,V,P,1.0,yes,o@x,a@x,oc@x,e@x,active,\n")
    idle = _decision(assets[0])
    h = assess_health(assets, [idle], _summary([idle]), today=TODAY)
    assert h.grade == BAD and h.unhandled_urgent == 1
    acted = _decision(assets[0], state=Action("acknowledged", "Dana", "", "2026-09-11T00:00:00Z"))
    h2 = assess_health(assets, [acted], _summary([acted]), today=TODAY)
    assert h2.grade == GOOD and h2.unhandled_urgent == 0 and h2.handled == 0
    fixed = _decision(assets[0], state=Action("fixed", "Dana", "", "2026-09-11T00:00:00Z"))
    assert assess_health(assets, [fixed], _summary([fixed]), today=TODAY).handled == 1


def test_over_budget_and_row_warnings_are_warnings():
    assets = parse_inventory(FULL + "A,V,P,1.0,maybe,o@x,a@x,oc@x,e@x,active,\n")
    ds = [_decision(assets[0]) for _ in range(3)]
    for d in ds:
        d.state = Action("acknowledged", "Dana", "", "2026-09-11T00:00:00Z")
    s = _summary(ds, budget=2, warnings=["Row 2 (A): internet_exposed 'maybe' is not one of ..."])
    h = assess_health(assets, ds, s, today=TODAY)
    labels = {c.label: c for c in h.checks}
    assert labels["Nobody is over their notice budget"].status == WARN and "o@x" in labels["Nobody is over their notice budget"].detail
    assert h.grade == WARN and h.word == "Mostly ready"
