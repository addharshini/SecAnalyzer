import os, json
from typing import List, Dict
from markdown2 import markdown
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.utils import simpleSplit

from cwe_mapper import cwe_title, normalize_severity

def ensure_dirs(path_no_ext: str):
    out_dir = os.path.dirname(os.path.abspath(path_no_ext))
    os.makedirs(out_dir, exist_ok=True)

def save_json(findings: List[Dict], path_no_ext: str):
    ensure_dirs(path_no_ext)
    with open(path_no_ext + ".json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

def save_md(findings: List[Dict], path_no_ext: str, target_path_list=None):
    ensure_dirs(path_no_ext)
    lines = ["# Vulnerability Report", ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"## Finding #{i}")
        lines.append(f"- File: `{f['file']}`")
        lines.append(f"- Rule: **{f['rule_id']}**")
        lines.append(f"- Issue: {f['description']}")
        lines.append(f"- CWE: **{f['cwe']} — {cwe_title(f['cwe'])}**")
        lines.append(f"- Severity: **{normalize_severity(f.get('severity','LOW'))}**")
        if target_path_list and f.get("target") in target_path_list:
            lines.append(f"- Target: `{f['target']}`")
        lines.append("")
        lines.append("### Code Snippet")
        lines.append("```")
        lines.append(f.get("snippet","\n").strip())
        lines.append("```")
        if f.get("llm_suggestion"):
            lines.append("### LLM Suggestion")
            lines.append(f.get("llm_suggestion",""))
        lines.append("---")
    content = "\n".join(lines)
    with open(path_no_ext + ".md", "w", encoding="utf-8") as f:
        f.write(content)
    return content

def save_pdf_from_md(md_text: str, path_no_ext: str):
    ensure_dirs(path_no_ext)
    pdf_path = path_no_ext + ".pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    margin = 0.75 * inch
    max_width = width - 2 * margin
    y = height - margin

    for line in md_text.splitlines():
        if line.startswith("# "):
            line = line[2:]
        elif line.startswith("## "):
            line = "  " + line[3:]
        elif line.startswith("### "):
            line = "    " + line[4:]
        wrapped = simpleSplit(line, "Helvetica", 10, max_width)
        for w in wrapped:
            if y < margin:
                c.showPage()
                y = height - margin
            c.setFont("Helvetica", 10)
            c.drawString(margin, y, w)
            y -= 12
    c.save()
    return pdf_path
