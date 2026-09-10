"""Match KEV advisories to inventory rows with an honest confidence tier.

Tiers: exact, likely, possible, none. KEV carries no version data, so a match
never claims a specific version is affected; that is stated on every alert.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from rapidfuzz import fuzz

from .inventory import Asset
from .kev import Advisory

# Vendor names that appear differently in KEV than in a typical inventory.
# Left side: what KEV says. Right side: names an inventory is likely to use.
VENDOR_ALIASES: dict[str, set[str]] = {
    "broadcom": {"vmware", "symantec", "brocade"},
    "synacor": {"zimbra"},
    "google": {"chromium", "chrome", "android"},
    "kludex": {"starlette", "encode"},
    "red hat": {"redhat", "rhel"},
    "microsoft": {"ms", "azure", "office", "windows"},
    "cisco": {"cisco systems"},
    "fortinet": {"fortigate", "fortios"},
    "sonicwall": {"sonic wall", "dell sonicwall"},
    "citrix": {"cloud software group", "netscaler"},
    "progress": {"progress software", "kemp", "ipswitch", "moveit"},
    "ivanti": {"pulse secure", "mobileiron"},
    "palo alto networks": {"palo alto", "pan"},
    "check point": {"checkpoint"},
    "n-able": {"nable", "solarwinds msp"},
    "papercut": {"paper cut"},
    "atlassian": {"jira", "confluence", "bitbucket"},
    "jetbrains": {"teamcity"},
    "apple": {"macos", "ios", "iphone"},
    "linux": {"linux kernel", "kernel"},
    "oracle": {"weblogic", "mysql", "java"},
    "adobe": {"magento"},
    "ubiquiti": {"ubnt", "unifi"},
    "wordpress": {"automattic"},
    "arista": {"velocloud"},
    "zoho": {"manageengine"},
    "connectwise": {"screenconnect"},
}
NOISE_TOKENS = {"inc", "corp", "corporation", "ltd", "llc", "co", "the", "and", "software", "technologies", "systems", "networks"}
MULTI_PRODUCT = {"multiple products", "multiple", "various products"}

EXACT_PRODUCT = 90
LIKELY_PRODUCT = 70
POSSIBLE_PRODUCT = 45
VENDOR_MATCH = 85


def normalize(s: str) -> str:
    s = s.lower().strip()
    s = s.replace("(", " ").replace(")", " ")  # keep acronyms like (ASA); people search by them
    s = re.sub(r"[^a-z0-9]+", " ", s)
    tokens = [t for t in s.split() if t not in NOISE_TOKENS]
    return " ".join(tokens)


def _nospace(s: str) -> str:
    return s.replace(" ", "")


def vendor_matches(inv_vendor: str, kev_vendor: str, kev_product: str) -> bool:
    iv, kv, kp = normalize(inv_vendor), normalize(kev_vendor), normalize(kev_product)
    if not iv:
        return False
    if iv == kv or fuzz.token_set_ratio(iv, kv) >= VENDOR_MATCH:
        return True
    # KEV often names the product with the vendor inside it ("VMware vCenter" under Broadcom).
    if iv in kp.split() or (len(iv) >= 4 and _nospace(iv) in _nospace(kp)):
        return True
    aliases = VENDOR_ALIASES.get(kv, set())
    return any(iv == normalize(a) or fuzz.token_set_ratio(iv, normalize(a)) >= VENDOR_MATCH for a in aliases)


GENERIC_PRODUCT_TOKENS = {
    "server", "servers", "appliance", "appliances", "platform", "edition", "enterprise", "suite",
    "os", "software", "product", "products", "service", "services", "system", "systems", "core",
}


def _tokens(s: str, drop: set[str]) -> list[str]:
    """Tokens of a normalized string minus vendor and generic words, unless that would leave nothing."""
    toks = normalize(s).split()
    kept = [t for t in toks if t not in drop]
    return kept or toks


def product_score(inv_vendor: str, inv_product: str, kev_product: str, kev_vendor: str = "") -> int:
    # Drop the vendor names themselves, never their aliases: aliases include product names
    # ("windows", "fortios") that must stay in the product comparison.
    vendor_words = set(normalize(inv_vendor).split()) | set(normalize(kev_vendor).split())
    drop = vendor_words | GENERIC_PRODUCT_TOKENS
    ip, kp = _tokens(inv_product, drop), _tokens(kev_product, drop)
    if not ip or not kp:
        return 0
    a, b = " ".join(ip), " ".join(kp)
    score = int(fuzz.token_set_ratio(a, b))
    # "SMA 1000" vs "SMA1000": with spaces removed one is contained in the other.
    an, bn = _nospace(a), _nospace(b)
    short, long_ = (an, bn) if len(an) <= len(bn) else (bn, an)
    if len(short) >= 4 and short in long_:
        score = 100
    # "ASA 5506" vs "... Adaptive Security Appliance (ASA) ...": every non-numeric inventory
    # token appears in the advisory product, so it is at least likely.
    alpha = [t for t in ip if not t.isdigit()]
    if score < LIKELY_PRODUCT and alpha and len("".join(alpha)) >= 3 and set(alpha) <= set(kp):
        score = LIKELY_PRODUCT
    return score


@dataclass(frozen=True)
class Match:
    advisory: Advisory
    asset: Asset
    tier: str  # exact | likely | possible
    score: int
    reason: str


def match_one(adv: Advisory, asset: Asset) -> Match | None:
    v_ok = vendor_matches(asset.vendor, adv.vendor, adv.product)
    p = product_score(asset.vendor, asset.product, adv.product, adv.vendor)
    kp = normalize(adv.product)

    if v_ok and kp in MULTI_PRODUCT:
        # "Multiple Products" advisories usually name the products in the description.
        named = _tokens(asset.product, set(normalize(asset.vendor).split()) | GENERIC_PRODUCT_TOKENS)
        desc = _nospace(normalize(adv.description))
        if named and all(len(t) >= 4 and t in desc for t in named):
            return Match(adv, asset, "likely", 80, f"{adv.vendor} advisory names {asset.product} in its description")
        return Match(adv, asset, "possible", p, f"{adv.vendor} advisory covers multiple products; yours may be one of them")
    if v_ok and p >= EXACT_PRODUCT:
        return Match(adv, asset, "exact", p, f"vendor and product names match ({p}%)")
    if v_ok and p >= LIKELY_PRODUCT:
        return Match(adv, asset, "likely", p, f"vendor matches; product name is close ({p}%)")
    if not asset.vendor and p >= EXACT_PRODUCT:
        return Match(adv, asset, "likely", p, f"product name matches ({p}%) but your row has no vendor")
    if v_ok and p >= POSSIBLE_PRODUCT:
        return Match(adv, asset, "possible", p, f"vendor matches; product name only partly matches ({p}%)")
    return None


def match_all(advisories: list[Advisory], assets: list[Asset]) -> list[Match]:
    out: list[Match] = []
    for adv in advisories:
        for asset in assets:
            m = match_one(adv, asset)
            if m:
                out.append(m)
    return out
