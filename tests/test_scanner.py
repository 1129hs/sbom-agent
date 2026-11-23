from pathlib import Path

from sbom_agent.scanner import missing_tools, parse_trivy

FIXTURES = Path(__file__).parent / "fixtures"


def test_missing_tools_empty_when_all_installed():
    assert missing_tools(["python3"]) == []


def test_missing_tools_returns_not_installed():
    assert missing_tools(["python3", "no-such-tool-xyz"]) == ["no-such-tool-xyz"]


def test_parse_trivy_skips_target_without_vulns():
    vulns = parse_trivy(FIXTURES / "trivy_sample.json")
    assert len(vulns) == 3


def test_parse_trivy_maps_fields():
    vulns = parse_trivy(FIXTURES / "trivy_sample.json")
    assert vulns[0] == {
        "pkg": "python-jose",
        "installed": "3.3.0",
        "id": "CVE-2024-33663",
        "severity": "CRITICAL",
        "fixed": "3.4.0",
        "title": "algorithm confusion with OpenSSH ECDSA keys",
    }


def test_parse_trivy_empty_fixed_becomes_none():
    vulns = parse_trivy(FIXTURES / "trivy_sample.json")
    assert vulns[1]["fixed"] is None
