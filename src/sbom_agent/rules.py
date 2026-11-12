# 패키지의 모든 취약점에 수정 버전이 있어야 업그레이드만으로 전부 해결 가능
def upgrade_fixes_all(vulns):
    return all(v.get("fixed") for v in vulns)
