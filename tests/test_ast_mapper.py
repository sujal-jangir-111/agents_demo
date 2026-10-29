from pathlib import Path

from common.ast_mapper import enclosing_function, extract_symbols, merge_symbols

DEMO_APP = Path(__file__).resolve().parent.parent / "demo_target_app" / "app.py"


def test_modules_and_calls():
    syms = extract_symbols("import yaml\nimport os.path\nyaml.load(x)\nos.getenv('A')\n")
    assert {"yaml", "os", "yaml.load", "os.getenv"} <= set(syms)


def test_alias_resolution():
    syms = extract_symbols("import numpy as np\nnp.linalg.norm(x)\n")
    assert "numpy" in syms and "numpy.linalg.norm" in syms


def test_from_import():
    syms = extract_symbols("from yaml import load as ld\nld(x)\nfrom a.b import c\n")
    assert {"yaml", "yaml.load", "a", "a.b.c"} <= set(syms)


def test_relative_imports_and_local_calls_ignored():
    syms = extract_symbols("from . import sibling\nfrom .x import y\ndef f(): pass\nf()\n")
    assert syms == []


def test_syntax_error_returns_empty():
    assert extract_symbols("def broken(:\n") == []


def test_merge_symbols_dedupes():
    assert merge_symbols(["import yaml", "import yaml\nimport json"]) == ["json", "yaml"]


def test_demo_app_symbols_prove_yaml_is_reachable():
    syms = extract_symbols(DEMO_APP.read_text(encoding="utf-8"))
    assert "yaml" in syms and "yaml.load" in syms
    assert "sqlite3.connect" in syms and "os.getenv" in syms
    assert "urllib3" not in syms  # pinned in requirements but never imported -> latent


def test_traceback_line_maps_to_checkout_handler():
    src = DEMO_APP.read_text(encoding="utf-8")
    lineno = next(i for i, ln in enumerate(src.splitlines(), 1) if 'PRICING["discount_rate"]' in ln)
    assert enclosing_function(src, lineno) == "checkout"
    assert enclosing_function(src, 1) is None
