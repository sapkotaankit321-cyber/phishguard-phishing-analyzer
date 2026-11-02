from pathlib import Path

from phishguard.email_analyzer import analyze_email_file

S = Path(__file__).parent.parent / "samples"


def test_paypal_phish_is_flagged():
    r = analyze_email_file(S / "paypal_credential_phish.eml")
    ids = {f.rule_id for f in r.findings}
    assert r.verdict == "PHISHING"
    assert {"EML001", "EML003", "EML004", "EML006"} <= ids


def test_malware_attachment():
    r = analyze_email_file(S / "invoice_malware.eml")
    assert "EML007" in {f.rule_id for f in r.findings}
    assert r.verdict == "PHISHING"


def test_legit_is_safe():
    r = analyze_email_file(S / "legit_newsletter.eml")
    assert r.verdict == "LIKELY SAFE"
    assert r.score == 0
