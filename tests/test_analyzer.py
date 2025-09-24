import json, os, subprocess, sys, pathlib

def test_runs_and_creates_reports():
    root = pathlib.Path(__file__).resolve().parents[1]
    cmd = [sys.executable, "src/analyzer.py", "--path", "examples/vulnerable_code", "--report", "reports/test_report", "--use-llm", "false"]
    subprocess.check_call(cmd, cwd=str(root))
    assert (root / "reports/test_report.md").exists()
    assert (root / "reports/test_report.pdf").exists()
    assert (root / "reports/test_report.json").exists()
    with open(root / "reports/test_report.json","r",encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert any(f["rule_id"] == "SQLI_STR_CONCAT" for f in data)
