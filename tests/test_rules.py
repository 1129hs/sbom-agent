from pathlib import Path

from sbom_agent.rules import upgrade_fixes_all
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
