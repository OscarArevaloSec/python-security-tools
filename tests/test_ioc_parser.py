"""Tests for IOC extraction, validation, and defanging."""
import ioc_parser


def _flat(results, key):
    return [original for original, _display in results.get(key, [])]


def test_ipv4_extracted_and_validated():
    r = ioc_parser.extract_iocs("beacon to 203.0.113.50 now", ["ip"], defang_output=False)
    assert "203.0.113.50" in _flat(r, "ip")


def test_ipv4_invalid_octet_dropped():
    r = ioc_parser.extract_iocs("bad 999.1.1.1 good 8.8.8.8", ["ip"], defang_output=False)
    ips = _flat(r, "ip")
    assert "8.8.8.8" in ips
    assert "999.1.1.1" not in ips


def test_ipv6_full_address_not_truncated():
    r = ioc_parser.extract_iocs("c2 at 2001:db8::1 here", ["ipv6"], defang_output=False)
    assert "2001:db8::1" in _flat(r, "ipv6")


def test_ipv6_canonical_dedup():
    r = ioc_parser.extract_iocs("2001:DB8::1 and 2001:db8::1", ["ipv6"], defang_output=False)
    assert _flat(r, "ipv6") == ["2001:db8::1"]


def test_timestamp_not_treated_as_ipv6():
    r = ioc_parser.extract_iocs("logged at 12:34:56 today", ["ipv6"], defang_output=False)
    assert _flat(r, "ipv6") == []


def test_domain_inside_url_is_deduped():
    r = ioc_parser.extract_iocs(
        "visit http://bad.com/x and also evil.com", ["url", "domain"], defang_output=False
    )
    domains = _flat(r, "domain")
    assert "evil.com" in domains
    assert "bad.com" not in domains  # already represented by the URL


def test_defang_url_and_email():
    assert ioc_parser.defang("http://bad.com/x", "url") == "hxxp://bad[.]com/x"
    assert ioc_parser.defang("a@b.com", "email") == "a[@]b[.]com"
