from datetime import date

import pytest

from patchowner.inventory import Asset
from patchowner.kev import Advisory
from patchowner.ssvc import AUTOMATABLE, POINTS, Policy, PolicyError, assess, automatable_hint, plain_policy


def adv(description="Remote code execution over the network."):
    return Advisory(cve_id="CVE-2026-0001", vendor="V", product="P", name="", description=description,
                    required_action="Apply update.", date_added=date(2026, 9, 1), due_date=None, ransomware_known=False)


def test_default_policy_is_complete():
    p = Policy.default()
    expected = 1
    for pt in POINTS:
        expected *= len(pt.values)
    assert len(p.rows) == expected == 72


@pytest.mark.parametrize("values,outcome,row", [
    (("none", "small", "no", "low"), "defer", 0),
    (("active", "small", "no", "low"), "scheduled", 48),
    (("active", "open", "yes", "high"), "immediate", 70),
    (("active", "open", "no", "very high"), "immediate", 67),
    (("active", "controlled", "yes", "medium"), "out-of-cycle", 61),
])
def test_default_policy_rows(values, outcome, row):
    assert Policy.default().outcome_for(values) == (outcome, row)


def test_policy_rejects_incomplete_or_bad_values():
    with pytest.raises(PolicyError, match="72"):
        Policy.parse("row,E,Se,A,H,out\n0,none,small,no,low,defer\n", "x")
    with pytest.raises(PolicyError, match="not a valid"):
        Policy.parse("row,E,Se,A,H,out\n0,none,small,no,low,someday\n", "x")


def test_policy_round_trips_to_csv():
    p = Policy.default()
    again = Policy.parse(p.to_csv(), "again")
    assert again.rows == p.rows


def test_assess_internet_facing_high_production_is_open_yes_high():
    a = assess(adv(), Asset(asset="vpn", vendor="V", product="P", internet_exposed=True, criticality="high"))
    assert a.values == ("active", "open", "yes", "high")
    assert a.steps[1].fact and not a.steps[3].fact
    assert a.vector() == "SSVCv2/A:Y/E:A/H:H/Se:O/"


def test_assess_staging_is_low_impact_and_internal_is_controlled():
    a = assess(adv(), Asset(asset="b", vendor="V", product="P", environment="staging", criticality="high"))
    assert a.values == ("active", "controlled", "yes", "low")


def test_inventory_overrides_win():
    a = assess(adv(), Asset(asset="b", vendor="V", product="P", exposure="small", human_impact="very high"))
    assert a.values[1] == "small" and a.values[3] == "very high" and a.steps[1].fact and a.steps[3].fact


def test_automatable_defaults_to_worst_case_and_only_raises_a_question():
    a = assess(adv("allows an authenticated attacker to execute code"), Asset(asset="b", vendor="V", product="P"))
    step = a.steps[2]
    assert step.value == "yes" and not step.fact and "authenticated" in step.question
    assert a.questions == [step.question]
    assert assess(adv(), Asset(asset="b", vendor="V", product="P")).questions == []


def test_a_person_can_confirm_it_needs_help():
    a = assess(adv("needs user interaction"), Asset(asset="b", vendor="V", product="P"))
    b = a.with_value(AUTOMATABLE, "no")
    assert b.values[2] == "no" and b.steps[2].fact and b.questions == []


@pytest.mark.parametrize("text,expected", [
    ("allows an authenticated attacker to execute code", "authenticated attacker"),
    ("requires user interaction to open a crafted file", "user interaction"),
    ("allows a remote attacker to execute arbitrary code via crafted packets", ""),
    ("could allow a remote unauthenticated attacker to cause requests", ""),
])
def test_automatable_hint(text, expected):
    assert automatable_hint(text) == expected


def test_because_reads_plainly():
    a = assess(adv(), Asset(asset="b", vendor="V", product="P", internet_exposed=True, criticality="high"))
    assert a.because() == "it's reachable from the internet, the attack can run by itself, and it would hurt a lot"


def test_plain_policy_collapses_the_default_tree_to_six_lines():
    lines = plain_policy(Policy.default())
    assert len(lines) == 6
    assert lines[0] == "Reachable from the internet and the attack can run by itself: Update soon; Act now if it would hurt a lot or more."
    assert lines[2] == "Reachable from inside only and the attack can run by itself: Update soon."


def test_plain_policy_merges_when_automatable_does_not_matter():
    p = Policy.default()
    for hi in ("low", "medium", "high", "very high"):
        p.rows[("active", "open", "yes", hi)] = ("immediate", 0)
        p.rows[("active", "open", "no", hi)] = ("immediate", 0)
    assert plain_policy(p)[0] == "Reachable from the internet: Act now."
