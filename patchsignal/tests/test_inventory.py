import pytest

from patchsignal.inventory import InventoryError, parse_inventory


def test_parses_headers_case_and_space_insensitively():
    rows = parse_inventory("Asset,Vendor,Product,Internet Exposed,Owner Email\nvpn,Fortinet,FortiOS,Yes,D@X\n")
    a = rows[0]
    assert a.internet_exposed and a.owner_email == "d@x" and a.environment == "production"


def test_missing_required_column_is_a_clear_error():
    with pytest.raises(InventoryError, match="Missing required column"):
        parse_inventory("asset,product\nvpn,FortiOS\n")


def test_bad_exception_date_is_a_warning_not_a_crash():
    a = parse_inventory("asset,vendor,product,exception_until\nx,V,P,soon\n")[0]
    assert a.exception_until is None and a.warnings
