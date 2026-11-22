from sbom_agent.usage import import_name


def test_import_name_uses_table_when_names_differ():
    assert import_name("pillow") == "PIL"
    assert import_name("python-jose") == "jose"


def test_import_name_ignores_case():
    assert import_name("Pillow") == "PIL"


def test_import_name_default_replaces_dash():
    assert import_name("anyio") == "anyio"
    assert import_name("typing-extensions") == "typing_extensions"
