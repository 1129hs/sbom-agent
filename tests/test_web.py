from pathlib import Path

from fastapi.testclient import TestClient

from sbom_agent.web import create_app

REPORT_DIR = Path(__file__).parent / "fixtures" / "report"
client = TestClient(create_app(REPORT_DIR, target="demo-app"))


def test_list_page_shows_packages_in_order():
    res = client.get("/")
    assert res.status_code == 200
    text = res.text
    assert text.index("python-jose") < text.index("pillow") < text.index("anyio")


def test_list_page_filters_by_impact():
    res = client.get("/", params={"impact": "확인 필요"})
    assert "anyio" in res.text
    assert "python-jose" not in res.text


def test_list_page_shows_action_label():
    res = client.get("/")
    assert "업그레이드 → 13.0.0" in res.text
