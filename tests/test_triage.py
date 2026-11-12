from pathlib import Path

from sbom_agent.triage import load_vulns, parse_json


def test_parse_json_plain():
    result = parse_json('{"impact": "낮음"}')
    assert result == {"impact": "낮음"}


def test_parse_json_code_block():
    text = '```json\n{"impact": "낮음"}\n```'
    result = parse_json(text)
    assert result == {"impact": "낮음"}


def test_parse_json_invalid():
    result = parse_json("이건 JSON 아님")
    assert result is None


FIXTURES = Path(__file__).parent / "fixtures"


def test_load_vulns_groups_by_package():
    grouped = load_vulns(FIXTURES / "vulns_sample.json")
    assert set(grouped) == {"python-jose", "pillow", "anyio"}
    assert len(grouped["python-jose"]) == 2
