import shutil
from pathlib import Path

from sbom_agent.report import load_report

REPORT_DIR = Path(__file__).parent / "fixtures" / "report"


def test_load_report_sorts_by_impact_then_vuln_count():
    rows = load_report(REPORT_DIR)
    assert [r["pkg"] for r in rows] == ["python-jose", "pillow", "anyio"]


def test_load_report_merges_three_files():
    jose = load_report(REPORT_DIR)[0]
    assert jose["installed"] == "3.3.0"
    assert jose["vuln_count"] == 2
    assert jose["usage"][0]["file"] == "auth.py"
    assert jose["action"] == "replace"
    assert len(jose["warnings"]) == 1


def test_load_report_without_triage(tmp_path):
    # --no-llm으로 스캔하면 triage.json이 없음
    shutil.copy(REPORT_DIR / "vulns.json", tmp_path)
    shutil.copy(REPORT_DIR / "usage.json", tmp_path)

    rows = load_report(tmp_path)
    assert all(r["impact"] is None for r in rows)
    assert rows[0]["pkg"] == "python-jose"
