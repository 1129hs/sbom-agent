from sbom_agent.scanner import missing_tools


def test_missing_tools_empty_when_all_installed():
    assert missing_tools(["python3"]) == []


def test_missing_tools_returns_not_installed():
    assert missing_tools(["python3", "no-such-tool-xyz"]) == ["no-such-tool-xyz"]
