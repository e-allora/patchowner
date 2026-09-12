"""The five routing scenarios from the PatchOwner doc, as written.

Principle: send the detailed alert to the person who can fix it, a concise status to the person
accountable for it, and an escalation only to the person who can remove a blocker.
"""
from datetime import date

from patchowner.decide import ACT_NOW, UPDATE_SOON, decide
from patchowner.inventory import Asset
from patchowner.kev import Advisory
from patchowner.matching import Match

TODAY = date(2026, 9, 10)


def adv(vendor, product, description="Remote code execution over the network."):
    return Advisory(cve_id="CVE-2026-1", vendor=vendor, product=product, name="", description=description,
                    required_action="Apply update.", date_added=date(2026, 9, 1), due_date=None, ransomware_known=False)


def route(asset, advisory):
    return decide([Match(advisory, asset, "exact", 100, "r")], fallback_email="security@x", fallback_name="Security", today=TODAY)[0]


def emails(recipients):
    return [r.email for r in recipients]


def test_actively_exploited_vpn():
    d = route(Asset(asset="VPN", vendor="Fortinet", product="FortiOS", internet_exposed=True, criticality="high",
                    owner_email="netops@x", owner_name="Network Operations", oncall="soc@x",
                    accountable="infra-owner@x", escalate_to="ciso@x"), adv("Fortinet", "FortiOS"))
    assert d.urgency == ACT_NOW
    assert emails(d.fixers) == ["netops@x", "soc@x"]           # detail: network operations + security on-call
    assert d.accountable.email == "infra-owner@x"                # status: infrastructure owner
    assert d.escalation.email == "ciso@x" and d.delivery.escalate_after == "24 hours"  # CISO only if unresolved


def test_vulnerable_npm_dependency_in_production_service():
    d = route(Asset(asset="Checkout service", vendor="npm", product="lodash", criticality="high",
                    owner_email="repo-owner@x", accountable="eng-manager@x", escalate_to="champion@x"),
              adv("npm", "lodash"))
    assert d.urgency == UPDATE_SOON                              # internal, so not immediate under the default policy
    assert emails(d.fixers) == ["repo-owner@x"]                  # on-call is not woken for out-of-cycle
    assert d.accountable.email == "eng-manager@x"
    assert d.escalation.email == "champion@x" and d.delivery.escalate_after == "7 days"


def test_browser_patch_for_managed_laptops():
    d = route(Asset(asset="Managed laptops", vendor="Google", product="Chrome", criticality="medium",
                    owner_email="endpoint@x", accountable="itops-lead@x", escalate_to="helpdesk@x"),
              adv("Google", "Chromium V8", "requires user interaction to visit a crafted page"))
    assert emails(d.fixers) == ["endpoint@x"]
    assert d.accountable.email == "itops-lead@x"
    assert d.escalation.email == "helpdesk@x"                    # help desk only if it becomes stuck
    assert d.questions                                           # the text hint asks a person, never downgrades


def test_vulnerable_payment_system():
    d = route(Asset(asset="Payments", vendor="Adobe", product="Magento", internet_exposed=True, human_impact="very high",
                    owner_email="app-owner@x", oncall="infra-sec@x", accountable="finance-owner@x", escalate_to="cfo@x"),
              adv("Adobe", "Commerce and Magento"))
    assert d.urgency == ACT_NOW
    assert emails(d.fixers) == ["app-owner@x", "infra-sec@x"]
    assert d.accountable.email == "finance-owner@x"
    assert d.escalation.email == "cfo@x"


def test_cloud_control_plane():
    d = route(Asset(asset="Kubernetes control plane", vendor="Kubernetes", product="kube-apiserver", exposure="controlled",
                    criticality="critical", owner_email="cloud-platform@x", oncall="security@x",
                    accountable="cloud-owner@x", escalate_to="cto@x"), adv("Kubernetes", "kube-apiserver"))
    assert d.assessment.values == ("active", "controlled", "yes", "very high")
    assert d.accountable.email == "cloud-owner@x" and d.escalation.email == "cto@x"
    assert "cloud-platform@x" in emails(d.fixers)


def test_accountable_status_line_has_no_technical_detail():
    d = route(Asset(asset="VPN", vendor="Fortinet", product="FortiOS", internet_exposed=True, criticality="high",
                    owner_email="netops@x", owner_name="Dana", accountable="marco@x"), adv("Fortinet", "FortiOS"))
    line = d.status_line
    assert line.startswith("VPN: act now. Assigned to Dana. Acknowledge within 2 hours, plan within 8 hours.")
    assert "CVE" not in line and "Remote code" not in line


def test_no_owner_means_fallback_fixes_and_nobody_is_accountable_or_escalated():
    d = route(Asset(asset="Printer", vendor="PaperCut", product="MF", criticality="low"), adv("PaperCut", "NG/MF"))
    assert emails(d.fixers) == ["security@x"] and d.recipient_is_fallback
    assert d.accountable is None and d.escalation is None


def test_accountable_gets_one_status_line_per_asset_not_per_advisory():
    from patchowner.decide import summarize
    a = Asset(asset="VPN", vendor="Fortinet", product="FortiOS", internet_exposed=True, criticality="high",
              owner_email="netops@x", accountable="marco@x")
    ds = decide([Match(adv("Fortinet", "FortiOS"), a, "exact", 100, "r"), Match(adv("Fortinet", "FortiOS"), a, "exact", 100, "r")],
                fallback_email="security@x", today=TODAY)
    s = summarize(ds, days=90, catalog_version="v", policy_name="p", advisories_in_window=2, assets=1, budget=10, warnings=[])
    assert len(s.status_lines["marco@x"]) == 1 and s.by_person["marco@x"]["status"] == 1
    assert s.by_person["netops@x"]["fixer"] == 2
