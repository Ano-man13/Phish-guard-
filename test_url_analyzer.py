import pytest

from app.services.errors import InvalidInput
from app.services.risk_engine import assess
from app.services.url_analyzer import analyze_url


def keys(url):
    return {f.key for f in analyze_url(url).findings}


def level(url):
    return assess(analyze_url(url).findings)


def test_plain_https_url_is_low_with_no_findings():
    result = level("https://example.com")
    assert result.level == "LOW"
    assert result.score == 0
    assert result.findings == []


def test_http_is_flagged():
    assert "http_scheme" in keys("http://example.com")


def test_https_not_flagged_for_scheme():
    assert "http_scheme" not in keys("https://example.com/page")


def test_ip_url_is_flagged():
    assert "ip_host" in keys("http://203.0.113.9/")


def test_obfuscated_ip_flagged():
    assert "ip_host" in keys("http://3232235777/")
    assert "ip_host" in keys("http://0x7f.0.0.1/")


def test_ipv6_literal_flagged():
    assert "ip_host" in keys("http://[2001:db8::1]/login")


def test_sample_ip_login_is_high_or_critical():
    assert level("http://192.168.1.50/login").level in ("HIGH", "CRITICAL")


def test_login_url_alone_is_only_low():
    result = level("https://example.com/login")
    assert result.level == "LOW"
    assert "login_words" in {f.key for f in result.findings}


def test_keyword_stuffed_but_otherwise_clean_url_stays_below_medium():
    result = level("https://example.com/login/verify/password/confirm")
    assert result.score <= 29
    assert result.level == "LOW"


def test_suspicious_url_is_high_or_critical():
    result = level("http://paypal-secure-login.example-verify.com/signin?password=1")
    assert result.level in ("HIGH", "CRITICAL")
    assert {"impersonation", "http_scheme", "credential_param"} <= {f.key for f in result.findings}


def test_userinfo_trick_detected():
    found = analyze_url("https://paypal.com@evil.example/login").findings
    assert any(f.key == "userinfo" for f in found)


def test_punycode_and_unicode_hosts():
    assert "lookalike_chars" in keys("https://xn--pypal-4ve.com/")
    assert "lookalike_chars" in keys("https://pаypal.com/")  # Cyrillic 'а'


def test_many_subdomains():
    assert "many_subdomains" in keys("https://a.b.c.d.example.com/")
    assert "many_subdomains" not in keys("https://www.mail.example.com/")


def test_odd_port():
    assert "odd_port" in keys("https://example.com:8443/")
    assert "odd_port" not in keys("https://example.com:443/")


def test_brand_in_subdomain_flagged_but_real_brand_not():
    assert "impersonation" in keys("https://paypal.com.evil.example/")
    assert "impersonation" not in keys("https://www.paypal.com/signin")
    assert "impersonation" not in keys("https://mail.google.com/")
    assert "impersonation" not in keys("https://pineapple.com/")


def test_two_part_suffix_registered_domain():
    details = dict(analyze_url("https://login.example.co.uk/").details)
    assert details["Domain"] == "example.co.uk"
    assert details["Subdomain"] == "login"


def test_redirect_and_embedded_url():
    assert "redirect_param" in keys("https://example.com/go?next=https://evil.example")
    assert "embedded_url" in keys("https://example.com/https://other.example/login")


def test_many_encoded_chars():
    assert "encoded_chars" in keys("https://example.com/a%20b%20c%20d%20e%20f")


def test_long_url_minor():
    assert "long_url" in keys("https://example.com/" + "a" * 120)


def test_missing_scheme_is_analyzed_without_http_penalty():
    result = analyze_url("example.com/login")
    assert "http_scheme" not in {f.key for f in result.findings}
    assert dict(result.details)["Scheme"] == "not included"


def test_host_with_port_but_no_scheme():
    assert dict(analyze_url("example.com:8080/x").details)["Port"] == "8080"


def test_url_in_query_without_scheme_is_not_misread_as_scheme():
    analyze_url("example.com/r?u=http://x.example")  # must not raise


@pytest.mark.parametrize("bad", [
    "http://", "https:///path", "http://[abc", "javascript:alert(1)", "ftp://example.com",
    "mailto:a@example.com", "not a url", "http://exa mple.com", "http://localhost/",
    "http://example..com/", "https://example.com:99999/", "hello",
])
def test_malformed_input_raises_invalid_input(bad):
    with pytest.raises(InvalidInput):
        analyze_url(bad)
