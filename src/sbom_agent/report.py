import json
from pathlib import Path

from sbom_agent.triage import group_by_package

# 화면에 보여줄 순서 (판별 안 한 패키지는 맨 뒤)
IMPACT_ORDER = ["영향 있음", "확인 필요", "낮음", "해당 없음"]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


# JSON 파일 읽기 (없으면 기본값)
def read_json(path, default):
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


# 정렬용 순위 (목록에 없으면 맨 뒤)
def rank(order, value):
    return order.index(value) if value in order else len(order)


# 결과 폴더의 세 파일을 패키지당 한 줄로 합침
def load_report(out_dir):
    out_dir = Path(out_dir)
    vulns = read_json(out_dir / "vulns.json", [])
    usage = read_json(out_dir / "usage.json", {})
    triage = {
        t["package"]: t["parsed"] or {} for t in read_json(out_dir / "triage.json", [])
    }

    rows = []
    for pkg, pkg_vulns in group_by_package(vulns).items():
        pkg_vulns = sorted(pkg_vulns, key=lambda v: rank(SEVERITY_ORDER, v["severity"]))
        parsed = triage.get(pkg, {})
        rows.append(
            {
                "pkg": pkg,
                "installed": pkg_vulns[0]["installed"],
                "vulns": pkg_vulns,
                "vuln_count": len(pkg_vulns),
                "top_severity": pkg_vulns[0]["severity"],
                "usage": usage.get(pkg, []),
                "impact": parsed.get("impact"),
                "action": parsed.get("action"),
                "recommended": parsed.get("recommended_version"),
                "reason": parsed.get("reason"),
                "warnings": parsed.get("rule_warnings", []),
            }
        )

    # 영향도 순 → 취약점 많은 순 → 이름 순
    rows.sort(
        key=lambda r: (rank(IMPACT_ORDER, r["impact"]), -r["vuln_count"], r["pkg"])
    )
    return rows
