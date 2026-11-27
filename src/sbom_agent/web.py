from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.templating import Jinja2Templates

from sbom_agent.report import IMPACT_ORDER, load_report

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent / "templates")
STEPS = ["SBOM 생성", "취약점 조회", "사용 위치", "LLM 판별", "규칙 검증"]
ACTION_LABELS = {
    "upgrade": "업그레이드",
    "replace": "교체",
    "monitor": "지켜보기",
    "none": "조치 없음",
}


# 조치를 사람이 읽기 좋은 문구로 (업그레이드면 목표 버전까지)
def action_label(row):
    action = row["action"]
    if action is None:
        return "판별 안 함"
    label = ACTION_LABELS.get(action, str(action))
    if action == "upgrade" and row["recommended"]:
        label += f" → {row['recommended']}"
    return label


# 필터 링크 목록 (전체 + 실제로 있는 영향도만)
def build_filters(rows, current):
    filters = [
        {"label": "전체", "count": len(rows), "href": "/", "active": current is None}
    ]
    for impact in IMPACT_ORDER:
        count = sum(1 for r in rows if r["impact"] == impact)
        if count:
            filters.append(
                {
                    "label": impact,
                    "count": count,
                    "href": "/?" + urlencode({"impact": impact}),
                    "active": current == impact,
                }
            )
    return filters


# 결과 폴더를 보여주는 웹 앱 생성 (요청마다 다시 읽어서 재스캔 결과가 바로 반영됨)
def create_app(out_dir, target=None):
    app = FastAPI(title="sbom-agent")

    @app.get("/")
    def list_page(request: Request, impact: str | None = None):
        rows = load_report(out_dir)
        for row in rows:
            row["action_label"] = action_label(row)
        shown = [r for r in rows if impact is None or r["impact"] == impact]
        return TEMPLATES.TemplateResponse(
            request,
            "list.html",
            {
                "target": target,
                "rows": shown,
                "rows_total": len(rows),
                "vuln_total": sum(r["vuln_count"] for r in rows),
                "high_total": sum(1 for r in rows if r["impact"] == "영향 있음"),
                "steps": STEPS,
                "filters": build_filters(rows, impact),
            },
        )

    @app.get("/packages/{pkg}")
    def detail_page(request: Request, pkg: str):
        row = next((r for r in load_report(out_dir) if r["pkg"] == pkg), None)
        if row is None:
            raise HTTPException(status_code=404, detail="패키지를 찾을 수 없습니다")
        row["action_label"] = action_label(row)
        return TEMPLATES.TemplateResponse(
            request, "detail.html", {"target": target, "row": row}
        )

    return app
