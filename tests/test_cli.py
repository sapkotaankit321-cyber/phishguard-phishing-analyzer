from pathlib import Path

from phishguard.cli import main

S = Path(__file__).parent.parent / "samples"


def test_cli_html_report(tmp_path):
    out = tmp_path / "r.html"
    code = main(["email", str(S), "--format", "html", "-o", str(out)])
    assert code == 2
    assert "PhishGuard Analysis Report" in out.read_text()


def test_cli_url_safe(capsys):
    assert main(["url", "https://github.com/trending"]) == 0
    assert "LIKELY SAFE" in capsys.readouterr().out
