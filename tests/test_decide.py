from datetime import date

from patchowner.decide import ACT_NOW, DEFER, PLAN_UPDATE, UPDATE_SOON, WATCH, decide, summarize
from patchowner.inventory import Asset
from patchowner.kev import Advisory
from patchowner.matching import Match
from patchowner.ssvc import Policy

TODAY = date(2026, 9, 9)


def adv(description="Bad thing over the network. More.", ransomware=False):
    return Advisory(cve_id="CVE-2026-0001", vendor="Fortinet", product="FortiOS", name="n", description=description,
                    required_action="Apply update. Then verify.", date_added=date(2026, 9, 1), due_date=date(2026, 9, 22),
                    ransomware_known=ransomware)


def dec(tier="exact", policy=None, description="Bad thing over the network. More.", **kw):
    a = Asset(asset="VPN", vendor="Fortinet", product="FortiOS", **kw)
    return decide([Match(adv(description), a, tier, 100, "r")], fallback_email="sec@x", today=TODAY, policy=policy)[0]


def test_internet_facing_high_production_is_act_now_with_cc():
    d = dec(internet_exposed=True, criticality="high", owner_email="dana@x", owner_name="Dana")
    assert d.urgency == ACT_NOW and d.outcome == "immediate" and d.policy_row == 70
    assert d.cc == ["sec@x"] and d.escalate_to == "sec@x" and d.escalate_after == "24 hours"
    assert [r.role for r in d.fixers] == ["fixer", "on-call"]


def test_internet_facing_medium_is_update_soon_under_sei_defaults():
    assert dec(internet_exposed=True, criticality="medium").urgency == UPDATE_SOON


def test_text_hint_never_lowers_urgency_but_asks_a_person():
    d = dec(description="An authenticated attacker can do a thing.", internet_exposed=True, criticality="high")
    assert d.urgency == ACT_NOW and d.assessment.values == ("active", "open", "yes", "high")
    assert len(d.questions) == 1 and d.alt_leaf_key == "active|open|no|high"


def test_isolated_low_is_plan_update():
    d = dec(exposure="small", criticality="low")
    assert d.urgency == PLAN_UPDATE and d.assessment.values == ("active", "small", "yes", "low")


def test_plain_reason_is_one_sentence():
    d = dec(internet_exposed=True, criticality="high")
    assert d.plain_reason == "Act now, because it's reachable from the internet, the attack can run by itself, and it would hurt a lot."
    w = dec(tier="possible")
    assert w.plain_reason.startswith("Watch, because we are not sure")


def test_possible_match_is_watch_with_no_path():
    d = dec(tier="possible", internet_exposed=True, criticality="high")
    assert d.urgency == WATCH and d.assessment is None and d.vector == ""


def test_custom_policy_defer_is_suppressed_with_reason():
    p = Policy.default()
    p.rows[("active", "open", "yes", "high")] = ("defer", 70)
    d = dec(policy=p, internet_exposed=True, criticality="high")
    assert d.urgency == DEFER and not d.sent and "defer" in d.suppressed_reason


def test_routing_uses_owner_else_fallback():
    d = dec(owner_email="Dana@X", owner_name="Dana")
    assert (d.recipient_email, d.recipient_is_fallback) == ("Dana@X", False)
    f = dec()
    assert (f.recipient_email, f.recipient_is_fallback) == ("sec@x", True)


def test_escalate_to_column_is_used():
    assert dec(owner_email="d@x", escalate_to="boss@x").escalate_to == "boss@x"


def test_retired_asset_is_suppressed_with_reason():
    d = dec(status="retired")
    assert not d.sent and "retired" in d.suppressed_reason


def test_exception_suppresses_until_expiry_only():
    assert not dec(exception_until=date(2026, 12, 31), exception_reason="behind WAF").sent
    assert dec(exception_until=date(2026, 1, 1)).sent


def test_facts_and_estimates_are_separated():
    d = dec(version="7.2.8")
    assert any("CISA confirms" in f for f in d.facts)
    assert any("7.2.8 was not checked" in e for e in d.estimates)


def test_path_text_reads_as_a_sentence():
    d = dec(internet_exposed=True, criticality="high")
    assert d.path_text == "Exploitation: active › System Exposure: open › Automatable: yes › Human Impact: high → immediate"


def test_summary_counts_and_budget():
    ds = [dec(internet_exposed=True, criticality="high", owner_email="a@x") for _ in range(3)]
    s = summarize(ds, days=90, catalog_version="v", policy_name="p", advisories_in_window=50, assets=1, budget=2, warnings=[])
    assert s.sent == 3 and s.by_urgency[ACT_NOW] == 3 and s.over_budget == {"a@x": 3}
    assert s.by_person["a@x"]["fixer"] == 3 and s.by_person["sec@x"]["fixer"] == 3  # on-call joins on Act now
