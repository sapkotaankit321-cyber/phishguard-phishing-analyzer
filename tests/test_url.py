from phishguard.url_analyzer import analyze_url, registered_domain, shannon_entropy


def ids(url):
    return {f.rule_id for f in analyze_url(url)}


def test_ip_host():
    assert "URL001" in ids("http://192.0.2.10/login")


def test_at_trick():
    assert "URL002" in ids("https://paypal.com@evil.top/")


def test_punycode():
    assert "URL003" in ids("https://xn--pple-43d.com")


def test_brand_outside_domain():
    assert "URL009" in ids("http://paypal.com.secure.xyz/")
    assert "URL009" not in ids("https://www.paypal.com/")


def test_clean_url_has_no_findings():
    assert ids("https://github.com/trending") == set()


def test_helpers():
    assert registered_domain("a.b.example.com") == "example.com"
    assert shannon_entropy("aaaa") == 0
