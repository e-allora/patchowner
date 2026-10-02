"""The report is one HTML file that takes text from outside (inventory, CISA) and must not let it run."""

from datetime import date

from patchowner.decide import decide, summarize
from patchowner.health import assess_health
from patchowner.inventory import Asset
from patchowner.kev import Advisory
from patchowner.matching import Match
from patchowner.report import _client_data, render_html, share_text
from patchowner.ssvc import Policy

TODAY = date(2026, 9, 10)
HOSTILE = "</script><script>alert(1)</script>"


def hostile_decisions():
    adv = Advisory(
        cve_id="CVE-2026-1",
        vendor="Fortinet",
        product="FortiOS",
        name="",
        description=HOSTILE,
        required_action="Apply update.",
        date_added=date(2026, 9, 1),
        due_date=None,
        ransomware_known=False,
    )
    asset = Asset(
        asset=HOSTILE,
        vendor="Fortinet",
        product="FortiOS",
        internet_exposed=True,
        criticality="high",
        owner_email="dana@x",
        owner_name="Dana",
    )
    return decide([Match(adv, asset, "exact", 100, "r")], fallback_email="sec@x", today=TODAY)


def test_client_data_cannot_close_the_script_tag():
    out = _client_data(Policy.default(), hostile_decisions(), share="s")
    assert "</script" not in out and "<" not in out and ">" not in out
    assert "\\u003c/script\\u003e" in out


def test_rendered_report_escapes_hostile_text_everywhere():
    ds = hostile_decisions()
    s = summarize(ds, days=90, catalog_version="2026.09.10", policy_name="p", advisories_in_window=1, assets=1, budget=10, warnings=[])
    h = assess_health([d.match.asset for d in ds], ds, s, today=TODAY)
    html = render_html(s, ds, Policy.default(), h, inventory_name="inventory.csv")
    # Exactly the page's own scripts: the theme bootstrap, the data block, and the behaviour script.
    assert html.count("<script") == 3 and html.count("</script>") == 3
    assert "alert(1)" in html  # the text is shown, as text
    assert "<script>alert(1)" not in html
    assert "Demo only, not security advice." in share_text(s, h, "inventory.csv")
