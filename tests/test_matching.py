from datetime import date

import pytest

from patchowner.inventory import Asset
from patchowner.kev import Advisory
from patchowner.matching import match_one, normalize


def adv(vendor, product):
    return Advisory(cve_id="CVE-2026-0001", vendor=vendor, product=product, name="", description="", required_action="",
                    date_added=date(2026, 9, 1), due_date=None, ransomware_known=False)


def asset(vendor, product, **kw):
    return Asset(asset="thing", vendor=vendor, product=product, **kw)


def tier(kv, kp, iv, ip):
    m = match_one(adv(kv, kp), asset(iv, ip))
    return m.tier if m else None


def test_normalize_drops_noise_and_parentheticals():
    assert normalize("Secure Firewall Management Center (FMC)") == "secure firewall management center fmc"
    assert normalize("Cisco Systems, Inc.") == "cisco"


@pytest.mark.parametrize("kv,kp,iv,ip,expected", [
    ("Microsoft", "SharePoint", "Microsoft", "SharePoint Server", "exact"),
    ("Microsoft", "SharePoint Server", "Microsoft", "SharePoint", "exact"),
    ("Fortinet", "FortiOS", "Fortinet", "FortiOS", "exact"),
    ("Fortinet", "FortiOS", "Fortinet", "Fortinet FortiOS", "exact"),
    ("SonicWall", "SMA1000 Appliances", "SonicWall", "SMA 1000", "exact"),
    ("Broadcom", "VMware vCenter", "VMware", "vCenter Server", "exact"),
    ("Synacor", "Zimbra Collaboration Suite (ZCS)", "Zimbra", "Zimbra Collaboration Suite", "exact"),
    ("Fortinet", "Multiple Products", "Fortinet", "FortiOS", "possible"),
    ("Citrix", "NetScaler ADC and NetScaler Gateway", "Citrix", "NetScaler Gateway", "exact"),
    ("Microsoft", "Windows", "Microsoft", "Windows Server", "exact"),
    ("Cisco", "Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) ", "Cisco", "ASA 5506", "likely"),
    ("Microsoft", "Windows Ancillary Function Driver for WinSock", "Microsoft", "Windows Server", "exact"),
    ("PaperCut", "NG/MF", "PaperCut", "PaperCut MF", "exact"),
])
def test_positive_matches(kv, kp, iv, ip, expected):
    assert tier(kv, kp, iv, ip) == expected


@pytest.mark.parametrize("kv,kp,iv,ip", [
    ("Cisco", "IOS", "Fortinet", "FortiOS"),          # vendor gate stops the substring coincidence
    ("Microsoft", "Windows", "Intuit", "QuickBooks Desktop"),
    ("Google", "Chromium V8", "Fortinet", "FortiOS"),
    ("Apple", "macOS", "Microsoft", "Windows Server"),
    ("Microsoft", "SQL Server", "Microsoft", "SharePoint Server"),   # "server" alone is not a match
    ("Microsoft", "SQL Server", "Microsoft", "Windows Server"),
    ("Microsoft", "Active Directory Federation Services", "Microsoft", "SharePoint Server"),
])
def test_no_match(kv, kp, iv, ip):
    assert tier(kv, kp, iv, ip) is None


def test_multiple_products_named_in_description_is_likely():
    a = adv("Fortinet", "Multiple Products")
    a = Advisory(**{**a.__dict__, "description": "Fortinet FortiOS, FortiSwitchManager, and FortiSASE contain a bug."})
    m = match_one(a, asset("Fortinet", "FortiOS"))
    assert m and m.tier == "likely"


def test_missing_vendor_still_matches_strong_product_name_as_likely():
    assert tier("JetBrains", "TeamCity", "", "TeamCity") == "likely"
