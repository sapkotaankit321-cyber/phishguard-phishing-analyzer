# PhishGuard Analysis Report

_Generated 2026-11-02 01:16 UTC_

| Artifact | Type | Score | Verdict |
|---|---|---|---|
| `samples/invoice_malware.eml` | email | 90 | **PHISHING** |
| `samples/legit_newsletter.eml` | email | 0 | **LIKELY SAFE** |
| `samples/paypal_credential_phish.eml` | email | 100 | **PHISHING** |

## samples/invoice_malware.eml
**Verdict:** PHISHING (score 90/100)

| Rule | Severity | Finding | Detail | MITRE ATT&CK |
|---|---|---|---|---|
| EML005 | medium | Urgency / pressure language | immediately, final notice | T1566 Phishing |
| EML007 | high | Risky attachment type | invoice_44871.pdf.exe | T1566.001 Spearphishing Attachment |
| URL001 | high | IP address used as host | 198.51.100.23 [http://198.51.100.23/files/invoice.zip] | T1566.002 Spearphishing Link |
| URL006 | low | Unencrypted HTTP link | http://198.51.100.23/files/invoice.zip [http://198.51.100.23/files/invoice.zip] | T1566.002 Spearphishing Link |
| URL010 | medium | Credential-lure keywords | invoice [http://198.51.100.23/files/invoice.zip] | T1566.002 Spearphishing Link |
| URL012 | high | Direct link to executable/archive | /files/invoice.zip [http://198.51.100.23/files/invoice.zip] | T1566.002 Spearphishing Link |

## samples/legit_newsletter.eml
**Verdict:** LIKELY SAFE (score 0/100)

No indicators found.

## samples/paypal_credential_phish.eml
**Verdict:** PHISHING (score 100/100)

| Rule | Severity | Finding | Detail | MITRE ATT&CK |
|---|---|---|---|---|
| EML001 | high | Reply-To domain differs from From | recovery@mail-verify-center.top vs alerts@paypa1-secure-support.xyz | T1566 Phishing |
| EML002 | medium | Return-Path domain mismatch | bounce@bulkmailer.tk | T1566 Phishing |
| EML003 | high | Display name spoofs another domain | 'PayPal Security (service@paypal.com)' <alerts@paypa1-secure-support.xyz> | T1656 Impersonation |
| EML004 | medium | SPF softfail | mx.example.com; spf=softfail smtp.mailfrom=paypa1-secure-support.xyz; dkim=none; dmarc=fail | T1566 Phishing |
| EML004 | medium | DKIM none | mx.example.com; spf=softfail smtp.mailfrom=paypa1-secure-support.xyz; dkim=none; dmarc=fail | T1566 Phishing |
| EML004 | high | DMARC fail | mx.example.com; spf=softfail smtp.mailfrom=paypa1-secure-support.xyz; dkim=none; dmarc=fail | T1566 Phishing |
| EML005 | medium | Urgency / pressure language | urgent, suspended, within 24 hours, verify your account, unusual activity | T1566 Phishing |
| EML006 | high | Link text does not match destination | shows www.paypal.com -> paypal.com.account-verify.login.secure-id.xyz | T1566.002 Spearphishing Link |
| URL004 | medium | High-abuse TLD | .xyz [http://paypal.com.account-verify.login.secure-id.xyz/signin?] | T1566.002 Spearphishing Link |
| URL006 | low | Unencrypted HTTP link | http://paypal.com.account-verify.login.secure-id.xyz/signin?session=8f7a [http://paypal.com.account-verify.login.secure-id.xyz/signin?] | T1566.002 Spearphishing Link |
| URL007 | medium | Excessive subdomains | paypal.com.account-verify.login.secure-id.xyz [http://paypal.com.account-verify.login.secure-id.xyz/signin?] | T1566.002 Spearphishing Link |
| URL009 | high | Brand name outside registered domain | 'paypal' on secure-id.xyz [http://paypal.com.account-verify.login.secure-id.xyz/signin?] | T1566.002 Spearphishing Link |
| URL010 | medium | Credential-lure keywords | login, verify, secure, account, signin [http://paypal.com.account-verify.login.secure-id.xyz/signin?] | T1566.002 Spearphishing Link |
