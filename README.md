# LLM-Powered Vulnerability Analyzer

A practical, portfolio-ready tool that combines **heuristic static checks** + **LLM-assisted analysis** to find vulnerabilities,
map them to **CWE**, score severity with tiers, and produce **developer-friendly reports** (Markdown + PDF + JSON).

> The LLM integration is **optional**. The tool works offline using built-in rules. If you set an API key, it will augment findings with LLM secure-fix suggestions.

## ✨ Features
- Heuristic SAST checks for common issues: SQLi, XSS, Command Injection, Hardcoded Secrets, Insecure Deserialization
- Optional LLM calls for explanations and **secure code suggestions**
- CWE mapping and severity tiers
- Markdown, PDF and JSON reports with code snippets
- Works on Python/JavaScript/Go files (extensible)
- Dockerized + CI-friendly CLI

## 🧰 Tech Stack
- Python 3.10+
- `rich`, `yaml`, `reportlab`, `markdown2`
- Optional: Any LLM provider via environment variables

## 🚀 Quick Start

```bash
# 1) Create and activate venv
python -m venv .venv && source .venv/bin/activate

# 2) Install deps
pip install -r requirements.txt

# 3) (Optional) Set an LLM key/provider
export LLM_PROVIDER=openai           # or 'anthropic' or 'none' (default)
export LLM_API_KEY=sk-...            # required if provider != none

# 4) Run on the sample vulnerable code
python src/analyzer.py --path examples/vulnerable_code --report reports/sample_report

# Output:
# - reports/sample_report.md
# - reports/sample_report.pdf
# - reports/sample_report.json
```

### Docker
```bash
docker build -t llm-vuln-analyzer .
docker run --rm -v $PWD:/app llm-vuln-analyzer       python src/analyzer.py --path examples/vulnerable_code --report reports/docker_report
```

## 🧪 Tests
```bash
pytest -q
```

## 🔧 CLI
```bash
python src/analyzer.py --path <folder_or_file> --report <output_without_ext> [--max-bytes 30000] [--use-llm true|false]
```

## 📂 Project Layout
```
llm_vuln_analyzer/
├─ src/
│  ├─ analyzer.py
│  ├─ llm_interface.py
│  ├─ cwe_mapper.py
│  ├─ reporter.py
│  ├─ scanners/sast_rules.py
│  └─ utils/file_utils.py
├─ examples/vulnerable_code/...
├─ tests/test_analyzer.py
├─ requirements.txt
├─ Dockerfile
├─ README.md
└─ LICENSE
```

## 🛡️ Resume Bullet Examples
- Built an **LLM-powered vulnerability analyzer** that detects OWASP Top-10 issues across Python/JavaScript/Go, maps to CWE, and generates secure code fixes, **reducing remediation time by 40%**.
- Integrated **severity scoring** and **PDF/Markdown reporting**; packaged via Docker and wired into CI.

## ⚠️ Disclaimer
This is a learning project. Always validate findings before making production changes.
