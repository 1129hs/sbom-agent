from pathlib import Path

from sbom_agent.rules import upgrade_fixes_all, validate_action
from sbom_agent.triage import load_vulns

FIXTURES = Path(__file__).parent / "fixtures"


# 수정 버전이 없는 취약점이 섞여 있으면 업그레이드로 다 못 고침
def test_upgrade_does_not_fix_when_any_fixed_is_null():
    grouped = load_vulns(FIXTURES / "vulns_sample.json")
    assert upgrade_fixes_all(grouped["python-jose"]) is False


# 모든 취약점에 수정 버전이 있으면 업그레이드로 고칠 수 있음
def test_upgrade_fixes_when_all_have_fixed_version():
    grouped = load_vulns(FIXTURES / "vulns_sample.json")
    assert upgrade_fixes_all(grouped["pillow"]) is True


# 수정 버전 없는 취약점이 있는데 upgrade라고 하면 replace로 바꾸고 경고를 남김
def test_validate_action_overrides_upgrade_when_unfixable():
    grouped = load_vulns(FIXTURES / "vulns_sample.json")
    llm_result = {"action": "upgrade", "recommended_version": "3.4.0"}

    result = validate_action(grouped["python-jose"], llm_result)

    assert result["action"] == "replace"
    assert "CVE-2026-85394" in result["rule_warnings"][0]
    assert result["recommended_version"] is None


# 모든 취약점이 업그레이드로 고쳐지면 LLM 결과를 그대로 둠
def test_validate_action_keeps_upgrade_when_fixable():
    grouped = load_vulns(FIXTURES / "vulns_sample.json")
    llm_result = {"action": "upgrade", "recommended_version": "13.0.0"}

    result = validate_action(grouped["pillow"], llm_result)

    assert result["action"] == "upgrade"
    assert result["rule_warnings"] == []
