from pathlib import Path

from sbom_agent.usage import find_usage, format_usage, import_name

DEMO_APP = Path(__file__).parent / "fixtures" / "demo-app"


def test_import_name_uses_table_when_names_differ():
    assert import_name("pillow") == "PIL"
    assert import_name("python-jose") == "jose"


def test_import_name_ignores_case():
    assert import_name("Pillow") == "PIL"


def test_import_name_default_replaces_dash():
    assert import_name("anyio") == "anyio"
    assert import_name("typing-extensions") == "typing_extensions"


def test_find_usage_finds_direct_import():
    hits = find_usage(DEMO_APP, "python-jose")
    assert [h["file"] for h in hits] == ["auth.py"]


def test_find_usage_uses_import_name():
    hits = find_usage(DEMO_APP, "pillow")
    assert [h["file"] for h in hits] == ["upload.py"]


def test_find_usage_empty_when_not_imported():
    assert find_usage(DEMO_APP, "anyio") == []


def test_format_usage_lists_file_line_and_code():
    hits = [{"file": "auth.py", "line": 1, "text": "from jose import jwt"}]
    assert format_usage(hits) == "auth.py:1  from jose import jwt"


def test_format_usage_when_no_hits():
    assert format_usage([]) == "직접 import 없음"
