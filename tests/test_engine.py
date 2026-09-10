"""End to end against the cached KEV feed. Skips if the feed has not been downloaded."""
from datetime import date
from pathlib import Path

import pytest

from patchsignal.engine import run_replay
from patchsignal.kev import DEFAULT_CACHE

EXAMPLE = Path(__file__).parent.parent / "examples" / "inventory.csv"


@pytest.mark.skipif(not DEFAULT_CACHE.exists(), reason="KEV feed not cached; run `patchsignal replay` once")
def test_example_inventory_replays_and_renders():
    r = run_replay(EXAMPLE.read_text(), inventory_name="example", days=90, today=date(2026, 9, 9))
    s = r.summary
    assert s.advisories_in_window > 0
    assert s.relevant_advisories < s.advisories_in_window, "most advisories must stay silent"
    assert "What PatchSignal would have told you" in r.html
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
