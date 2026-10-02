"""The upload-a-CSV web demo: every bad input gets a plain sentence back, never a stack trace."""

from fastapi.testclient import TestClient

from patchowner import web
from patchowner.kev import FeedError

CSV = b"asset,vendor,product\nHQ VPN,Fortinet,FortiOS\n"


def client(tmp_path) -> TestClient:
    web.configure(tmp_path / "state.json")
    return TestClient(web.app)


def post(c: TestClient, body: bytes = CSV, **form):
    data = {"days": "90", "fallback": "security@example.com", **form}
    return c.post("/replay", data=data, files={"inventory": ("inventory.csv", body, "text/csv")})


def test_index_is_the_form_with_the_disclaimer(tmp_path):
    r = client(tmp_path).get("/")
    assert r.status_code == 200
    assert "Run the replay" in r.text and "Not security advice" in r.text and "<code>asset</code>" in r.text


def test_days_out_of_range_is_explained(tmp_path):
    c = client(tmp_path)
    assert f"between {web.MIN_DAYS} and {web.MAX_DAYS} days" in post(c, days="0").text
    assert f"between {web.MIN_DAYS} and {web.MAX_DAYS} days" in post(c, days="99999").text


def test_oversized_upload_is_refused_before_parsing(tmp_path):
    row = b"x,y,z\n"
    big = b"asset,vendor,product\n" + row * (web.MAX_UPLOAD_BYTES // len(row) + 2)
    r = post(client(tmp_path), big)
    assert r.status_code == 200 and "larger than 5 MB" in r.text


def test_non_utf8_file_is_explained(tmp_path):
    r = post(client(tmp_path), b"\xff\xfe\x00bad")
    assert "not UTF-8 text" in r.text


def test_missing_columns_are_named(tmp_path):
    r = post(client(tmp_path), b"name,thing\nA,B\n")
    assert "Missing required column(s): asset, vendor, product" in r.text


def test_feed_problem_is_shown_in_the_form(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise FeedError("Could not download the CISA KEV catalog (test).")

    monkeypatch.setattr(web, "run_replay", boom)
    r = post(client(tmp_path))
    assert r.status_code == 200 and "Could not download the CISA KEV catalog" in r.text


def test_act_rejects_absurd_payloads(tmp_path):
    c = client(tmp_path)
    assert c.post("/act", json={"key": "", "action": "fixed"}).status_code == 422
    assert c.post("/act", json={"key": "k", "action": "fixed", "note": "n" * 5000}).status_code == 422
    assert c.post("/act", json={"key": "k", "action": "fixed", "by": "Dana"}).status_code == 200
