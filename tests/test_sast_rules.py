from pathlib import Path

import pytest

from common.sast_rules import mask_secret, scan_files, scan_text

ROOT = Path(__file__).resolve().parent.parent / "demo_target_app"
APP = (ROOT / "app.py").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")


def line_of(text: str, needle: str) -> int:
    return next(i for i, ln in enumerate(text.splitlines(), 1) if needle in ln)


def rules(findings):
    return {f.rule_id for f in findings}


def test_demo_app_intentional_vulnerabilities_detected():
    findings = scan_text("app.py", APP)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["HARDCODED_SECRET"].line_number == line_of(APP, "STRIPE_SECRET_KEY =")
    assert by_rule["UNSAFE_DESERIALIZATION"].line_number == line_of(APP, "yaml.load(")
    assert by_rule["SQL_INJECTION"].line_number == line_of(APP, "SELECT price FROM")
    assert rules(findings) == {"HARDCODED_SECRET", "UNSAFE_DESERIALIZATION", "SQL_INJECTION"}


def test_demo_app_secret_is_masked_everywhere():
    full = "sk_test_51SENTINELDEMOxxxxxxxx"
    for f in scan_text("app.py", APP):
        assert full not in f.code_snippet
    secret = next(f for f in scan_text("app.py", APP) if f.rule_id == "HARDCODED_SECRET")
    assert "sk_tes****" in secret.code_snippet


def test_demo_dockerfile_findings():
    findings = scan_text("Dockerfile", DOCKERFILE)
    assert rules(findings) == {"INSECURE_DOCKER"}
    lines = {f.line_number for f in findings}
    assert line_of(DOCKERFILE, "FROM python:latest") in lines
    assert line_of(DOCKERFILE, "EXPOSE 5678") in lines
    messages = " ".join(f.remediation_advice for f in findings)
    assert "USER" in messages and ":latest" in messages and "debug ports" in messages
    assert len(findings) == 3


def test_dockerfile_clean():
    clean = "FROM python:3.11-slim\nUSER app\nEXPOSE 8000\n"
    assert scan_text("Dockerfile", clean) == []


def test_dockerfile_9229_with_protocol():
    f = scan_text("Dockerfile", "FROM node:20\nUSER node\nEXPOSE 8080 9229/tcp\n")
    assert len(f) == 1 and f[0].line_number == 3


@pytest.mark.parametrize("code,rule", [
    ('k = "AKIAIOSFODNN7EXAMPLE"', "HARDCODED_SECRET"),
    ('t = "ghp_' + "a" * 36 + '"', "HARDCODED_SECRET"),
    ('t = "github_pat_' + "b" * 25 + '"', "HARDCODED_SECRET"),
    ('password = "hunter2hunter2"', "HARDCODED_SECRET"),
    ("eval(user_input)", "UNSAFE_EVAL"),
    ("exec(code)", "UNSAFE_EVAL"),
    ("yaml.load(data)", "UNSAFE_DESERIALIZATION"),
    ("pickle.loads(blob)", "UNSAFE_DESERIALIZATION"),
    ("subprocess.run(cmd, shell=True)", "COMMAND_INJECTION"),
    ("os.system('ls ' + x)", "COMMAND_INJECTION"),
    ('q = f"DELETE FROM t WHERE id={i}"', "SQL_INJECTION"),
    ('q = "SELECT * FROM t WHERE id=%s" % i', "SQL_INJECTION"),
    ('q = "UPDATE t SET a={}".format(i)', "SQL_INJECTION"),
])
def test_each_rule_fires(code, rule):
    assert rule in rules(scan_text("x.py", code + "\n"))


@pytest.mark.parametrize("code", [
    "yaml.safe_load(data)",
    "yaml.load(data, Loader=yaml.SafeLoader)",
    'cur.execute("SELECT * FROM t WHERE id = ?", (i,))',
    'password = os.getenv("DB_PASSWORD")',
    'password = "short"',
    "subprocess.run(cmd, shell=False)",
    "cursor.execute(q)",
    "# eval(x) is mentioned only in a comment",
])
def test_safe_code_not_flagged(code):
    assert scan_text("x.py", code + "\n") == []


def test_secret_in_comment_still_flagged_and_masked():
    f = scan_text("x.py", "# AKIAIOSFODNN7EXAMPLE\n")
    assert len(f) == 1 and "AKIAIO****" in f[0].code_snippet and "EXAMPLE" not in f[0].code_snippet


def test_other_finding_on_same_line_masks_secret():
    f = scan_text("x.py", 'eval("AKIAIOSFODNN7EXAMPLE")\n')
    assert {x.rule_id for x in f} == {"UNSAFE_EVAL", "HARDCODED_SECRET"}
    assert all("AKIAIOSFODNN7EXAMPLE" not in x.code_snippet for x in f)


def test_generic_secret_masks_value_only():
    f = scan_text("x.py", 'api_key = "abcdefghijklmnop"\n')
    assert f[0].code_snippet == 'api_key = "abcdef****"'


def test_mask_secret_helper():
    assert mask_secret("abcdefghij") == "abcdef****"
    assert mask_secret("ab") == "ab****"


def test_unknown_file_types_ignored_and_scan_files_ordering():
    assert scan_text("notes.md", "eval(x)") == []
    out = scan_files({"b.py": "eval(x)\n", "a.py": "exec(y)\n"})
    assert [f.file_path for f in out] == ["a.py", "b.py"]
