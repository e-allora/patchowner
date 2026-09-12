"""End to end against the cached KEV feed. Skips if the feed has not been downloaded."""
from datetime import date
from pathlib import Path

import pytest

from patchowner.engine import run_replay
from patchowner.kev import DEFAULT_CACHE

EXAMPLE = Path(__file__).parent.parent / "examples" / "inventory.csv"


@pytest.mark.skipif(not DEFAULT_CACHE.exists(), reason="KEV feed not cached; run `patchowner replay` once")
def test_example_inventory_replays_and_renders():
    r = run_replay(EXAMPLE.read_text(), inventory_name="example", days=90, today=date(2026, 9, 9))
    s = r.summary
    assert s.advisories_in_window > 0
    assert s.relevant_advisories < s.advisories_in_window, "most advisories must stay silent"
    assert "What PatchOwner would have told you" in r.html
    assert s.unowned >= 1  # the print server has no owner
    assert any(not d.sent for d in r.decisions)  # retired firewall or Tomcat exception
    assert "Your policy, in plain words" in r.html and "SSVCv2/" in r.html
    assert "Question for a person" in r.html
    assert any(d.assessment and d.outcome == "immediate" for d in r.decisions)


@pytest.mark.skipif(not DEFAULT_CACHE.exists(), reason="KEV feed not cached")
def test_card_ids_line_up_with_page_data():
    import json
    import re
    r = run_replay(EXAMPLE.read_text(), inventory_name="example", days=90, today=date(2026, 9, 10))
    data = json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', r.html, re.S).group(1))
    for m in re.finditer(r'<div class="card [^"]*" data-id="(\d+)" data-leaf="([^"]*)"', r.html):
        assert data["notices"][int(m.group(1))]["leaf"] == m.group(2)


def _policy_with_every_answer(tmp_path, answer):
    import csv
    from patchowner.ssvc import Policy
    src = Path(__file__).parent.parent / "patchowner" / "policies" / "deployer_default.csv"
    rows = list(csv.DictReader(src.open()))
    out = tmp_path / f"all_{answer}.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            r[list(r.keys())[-1]] = answer
            w.writerow(r)
    return Policy.load(out)


@pytest.mark.skipif(not DEFAULT_CACHE.exists(), reason="KEV feed not cached")
def test_slow_answers_carry_a_simulated_recommendation_caution(tmp_path):
    scheduled = run_replay(EXAMPLE.read_text(), inventory_name="example", days=90, today=date(2026, 9, 10),
                           policy=_policy_with_every_answer(tmp_path, "scheduled"))
    assert any(d.sent and d.outcome == "scheduled" for d in scheduled.decisions)
    assert "Simulated recommendation: Plan update, for testing the prioritization logic only" in scheduled.html
    assert '<p class="caution" data-caution ><b>' in scheduled.html   # visible, not hidden

    deferred = run_replay(EXAMPLE.read_text(), inventory_name="example", days=90, today=date(2026, 9, 10),
                          policy=_policy_with_every_answer(tmp_path, "defer"))
    assert all(not d.sent for d in deferred.decisions if d.outcome == "defer")
    assert "Simulated recommendation: Defer, for testing the prioritization logic only" in deferred.html
    assert "was not sent because the policy" in deferred.html


@pytest.mark.skipif(not DEFAULT_CACHE.exists(), reason="KEV feed not cached")
def test_disclaimer_is_sitewide_and_on_about_tab():
    r = run_replay(EXAMPLE.read_text(), inventory_name="example", days=90, today=date(2026, 9, 10))
    assert r.html.count("This site is for educational and testing purposes only") == 2   # About tab and footer
    assert "Demo for testing the prioritization logic only" in r.html                     # banner
    assert 'id="tab-about"' in r.html and "Business Source License" in r.html
    assert "Demo only, not security advice" in r.html                                     # share text
