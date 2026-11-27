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


def test_detail_page_shows_usage_vulns_and_warning():
    res = client.get("/packages/python-jose")
    assert res.status_code == 200
    assert "auth.py:1" in res.text
    assert "CVE-2026-85394" in res.text
    assert "수정 버전이 없는 취약점이 있어" in res.text


def test_detail_page_unknown_package_is_404():
    res = client.get("/packages/no-such-package")
    assert res.status_code == 404
