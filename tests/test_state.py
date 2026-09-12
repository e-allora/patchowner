from datetime import date, datetime, timezone

import pytest

from patchowner.decide import decide, summarize
from patchowner.inventory import Asset
from patchowner.kev import Advisory
from patchowner.matching import Match
from patchowner.state import StateStore, notice_key

TODAY = date(2026, 9, 10)


def adv(cve="CVE-2026-1"):
    return Advisory(cve_id=cve, vendor="Fortinet", product="FortiOS", name="", description="Remote code execution.",
                    required_action="Apply update.", date_added=date(2026, 9, 1), due_date=None, ransomware_known=False)


def asset(**kw):
    return Asset(asset="VPN", vendor="Fortinet", product="FortiOS", internet_exposed=True, criticality="high",
                 owner_email="dana@x", owner_name="Dana", accountable="marco@x", **kw)


def test_store_persists_and_reports_current_state(tmp_path):
    path = tmp_path / "state.json"
    s = StateStore(path)
    key = notice_key("CVE-2026-1", "VPN")
    s.record(key, "acknowledged", "Dana", at=datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc))
    s.record(key, "assigned", "Dana", "Priya")
    again = StateStore(path)
    assert again.current(key).action == "assigned" and again.current(key).note == "Priya"
    assert [a.action for a in again.history(key)] == ["acknowledged", "assigned"]
    assert again.current(key).sentence == "Assigned to Priya by Dana."


def test_reopen_clears_current_state_but_keeps_history(tmp_path):
    s = StateStore(tmp_path / "s.json"); key = "k"
    s.record(key, "fixed", "Dana"); s.record(key, "reopened", "Marco", "vendor patch was pulled")
    assert s.current(key) is None and len(s.history(key)) == 2


def test_unknown_action_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        StateStore(tmp_path / "s.json").record("k", "ignored", "Dana")


def test_not_applicable_suppresses_next_replay_with_the_persons_reason(tmp_path):
    s = StateStore(tmp_path / "s.json")
    s.record(notice_key("CVE-2026-1", "VPN"), "not_applicable", "Dana", "we run the fixed version")
    d = decide([Match(adv(), asset(), "exact", 100, "r")], fallback_email="sec@x", today=TODAY, state=s)[0]
    assert not d.sent and "Dana said this does not apply: we run the fixed version" in d.suppressed_reason
    assert d.state.action == "not_applicable" and d.history


def test_status_line_reflects_state(tmp_path):
    s = StateStore(tmp_path / "s.json"); key = notice_key("CVE-2026-1", "VPN")
    fresh = decide([Match(adv(), asset(), "exact", 100, "r")], fallback_email="sec@x", today=TODAY, state=s)[0]
    assert "Assigned to Dana. Acknowledge within 2 hours" in fresh.status_line
    s.record(key, "acknowledged", "Dana")
    ack = decide([Match(adv(), asset(), "exact", 100, "r")], fallback_email="sec@x", today=TODAY, state=s)[0]
    assert "Dana has acknowledged it. Plan due within 8 hours" in ack.status_line
    s.record(key, "fixed", "Dana", "patched to 7.2.9")
    fixed = decide([Match(adv(), asset(), "exact", 100, "r")], fallback_email="sec@x", today=TODAY, state=s)[0]
    assert fixed.status_line == "VPN: fixed. Fixed by Dana: patched to 7.2.9. Nothing needed from you."
    assert fixed.handled and not ack.handled  # acknowledged is not remediated


def test_summary_counts_states(tmp_path):
    s = StateStore(tmp_path / "s.json")
    s.record(notice_key("CVE-2026-2", "VPN"), "acknowledged", "Dana")
    ds = decide([Match(adv("CVE-2026-1"), asset(), "exact", 100, "r"), Match(adv("CVE-2026-2"), asset(), "exact", 100, "r")],
                fallback_email="sec@x", today=TODAY, state=s)
    sm = summarize(ds, days=90, catalog_version="v", policy_name="p", advisories_in_window=2, assets=1, budget=10, warnings=[])
    assert sm.by_state == {"open": 1, "acknowledged": 1, "assigned": 0, "fixed": 0}


def test_web_act_endpoint_records_and_rejects(tmp_path):
    from fastapi.testclient import TestClient

    from patchowner import web
    web.configure(tmp_path / "state.json")
    c = TestClient(web.app)
    r = c.post("/act", json={"key": "CVE-2026-1|VPN", "action": "acknowledged", "by": "Dana"})
    assert r.status_code == 200 and r.json()["state"]["sentence"] == "Acknowledged by Dana."
    assert c.post("/act", json={"key": "k", "action": "ignored", "by": "Dana"}).status_code == 400
    assert StateStore(tmp_path / "state.json").current("CVE-2026-1|VPN").action == "acknowledged"
