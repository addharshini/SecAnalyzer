import argparse
import os
from typing import List, Dict
from rich import print as rprint

from utils.file_utils import list_code_files, read_file
from scanners.sast_rules import detect_findings
from cwe_mapper import max_severity
from llm_interface import enrich_with_llm
import reporter

LANG_BY_EXT = {
    ".py": "py",
    ".js": "js",
    ".ts": "ts",
    ".go": "go",
}

def analyze_file(path: str, use_llm: bool, max_bytes: int) -> List[Dict]:
    code = read_file(path, max_bytes=max_bytes)
    lang = LANG_BY_EXT.get(os.path.splitext(path)[1].lower(), "py")
    base_findings = detect_findings(code, lang)
    findings = []
    for f in base_findings:
        f["file"] = path
        f["target"] = path
        if use_llm:
            f = enrich_with_llm(f)
        findings.append(f)
    return findings

def aggregate_severity(findings: List[Dict]) -> str:
    sev = "LOW"
    for f in findings:
        sev = max_severity(sev, f.get("severity","LOW"))
    return sev

def main():
    ap = argparse.ArgumentParser(description="LLM-Powered Vulnerability Analyzer")
    ap.add_argument("--path", required=True, help="File or folder to scan")
    ap.add_argument("--report", required=True, help="Output path without extension (md/pdf/json)")
    ap.add_argument("--max-bytes", type=int, default=30000, help="Max bytes per file to read")
    ap.add_argument("--use-llm", default="true", choices=["true","false"], help="Enable LLM suggestions (env required)")
    args = ap.parse_args()

    files = list_code_files(args.path)
    if not files:
        rprint(f"[yellow]No code files found under: {args.path}[/yellow]")
        return

    all_findings: List[Dict] = []
    for fp in files:
        rprint(f"[cyan]Scanning[/cyan] {fp}")
        file_findings = analyze_file(fp, use_llm=(args.use_llm == "true"), max_bytes=args.max_bytes)
        all_findings.extend(file_findings)

    if not all_findings:
        rprint("[green]No findings detected by heuristic rules.[/green]")

    reporter.save_json(all_findings, args.report)
    md_text = reporter.save_md(all_findings, args.report, target_path_list=files)
    reporter.save_pdf_from_md(md_text, args.report)

    rprint(f"[bold green]Reports written:[/bold green] {args.report}.md, .pdf, .json")
    rprint(f"[bold]Overall Severity:[/bold] {aggregate_severity(all_findings)}")

if __name__ == "__main__":
    main()
