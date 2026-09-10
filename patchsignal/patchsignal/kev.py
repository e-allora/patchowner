"""CISA Known Exploited Vulnerabilities feed: download, cache, and filter."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CACHE = Path(__file__).resolve().parent.parent / "data" / "kev.json"


@dataclass(frozen=True)
class Advisory:
    cve_id: str
    vendor: str
    product: str
    name: str
    description: str
    required_action: str
    date_added: date
    due_date: date | None
    ransomware_known: bool
    source: str = "CISA KEV"

    @property
    def url(self) -> str:
        return f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={self.cve_id}"


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    return date.fromisoformat(s[:10])


def parse_feed(raw: dict) -> list[Advisory]:
    out: list[Advisory] = []
    for v in raw.get("vulnerabilities", []):
        out.append(
            Advisory(
                cve_id=v["cveID"].strip(),
                vendor=v.get("vendorProject", "").strip(),
                product=v.get("product", "").strip(),
                name=v.get("vulnerabilityName", "").strip(),
                description=v.get("shortDescription", "").strip(),
                required_action=v.get("requiredAction", "").strip(),
                date_added=_parse_date(v.get("dateAdded")) or date.min,
                due_date=_parse_date(v.get("dueDate")),
                ransomware_known=v.get("knownRansomwareCampaignUse", "").strip().lower() == "known",
            )
        )
    return out


def load_feed(cache: Path = DEFAULT_CACHE, refresh: bool = False, timeout: int = 30) -> tuple[list[Advisory], str]:
    """Return (advisories, catalog_version). Downloads when the cache is missing or refresh is set."""
    if refresh or not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(KEV_URL, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            cache.write_bytes(resp.read())
    raw = json.loads(cache.read_text())
    return parse_feed(raw), str(raw.get("catalogVersion", "unknown"))


def in_window(advisories: list[Advisory], days: int, today: date | None = None) -> list[Advisory]:
    today = today or date.today()
    cutoff = today - timedelta(days=days)
    return sorted((a for a in advisories if a.date_added >= cutoff), key=lambda a: a.date_added, reverse=True)
