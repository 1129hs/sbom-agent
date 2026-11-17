# 패키지의 모든 취약점에 수정 버전이 있어야 업그레이드만으로 전부 해결 가능
def upgrade_fixes_all(vulns):
    return all(v.get("fixed") for v in vulns)


# LLM이 upgrade를 권했는데 업그레이드로 다 안 고쳐지면 replace로 바꾸고 경고를 남김
def validate_action(vulns, llm_result):
    result = dict(llm_result)
    result["rule_warnings"] = []

    if result.get("action") == "upgrade" and not upgrade_fixes_all(vulns):
        unfixed = [v["id"] for v in vulns if not v.get("fixed")]
        result["action"] = "replace"
        result["recommended_version"] = None
        result["rule_warnings"].append(
            f"수정 버전이 없는 취약점이 있어 업그레이드만으로 해결되지 않음: {', '.join(unfixed)}"
        )

    return result
