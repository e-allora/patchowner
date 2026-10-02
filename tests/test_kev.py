"""The KEV feed: a bad download or a bad cache is a FeedError with a sentence, not a traceback."""

import json
import urllib.error
import urllib.request
from datetime import date

import pytest

from patchowner import kev

FEED = {
    "catalogVersion": "2026.09.29",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1",
            "vendorProject": "Fortinet",
            "product": "FortiOS",
            "vulnerabilityName": "n",
            "shortDescription": "d",
            "requiredAction": "Apply updates.",
            "dateAdded": "2026-09-01",
            "dueDate": "2026-09-15",
            "knownRansomwareCampaignUse": "Known",
        }
    ],
}


def test_cached_feed_is_parsed(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(FEED))
    advisories, version = kev.load_feed(cache)
    assert version == "2026.09.29" and advisories[0].cve_id == "CVE-2026-1"
    assert advisories[0].ransomware_known and advisories[0].due_date == date(2026, 9, 15)


def test_download_failure_is_a_feed_error_and_leaves_no_cache(tmp_path, monkeypatch):
    def fail(*_a, **_k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    cache = tmp_path / "kev.json"
    with pytest.raises(kev.FeedError, match="Could not download"):
        kev.load_feed(cache)
    assert not cache.exists()


def test_corrupt_cache_is_a_feed_error(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text("{not json")
    with pytest.raises(kev.FeedError, match="not valid JSON"):
        kev.load_feed(cache)
    cache.write_text(json.dumps({"something": "else"}))
    with pytest.raises(kev.FeedError, match="does not look like the CISA KEV feed"):
        kev.load_feed(cache)


def test_window_keeps_recent_entries_newest_first():
    old = kev.parse_feed(FEED)[0]
    new = kev.Advisory("CVE-2026-2", "V", "P", "", "", "", date(2026, 9, 20), None, False)
    got = kev.in_window([old, new], days=30, today=date(2026, 9, 25))
    assert [a.cve_id for a in got] == ["CVE-2026-2", "CVE-2026-1"]
    assert kev.in_window([old, new], days=3, today=date(2026, 9, 25)) == []
