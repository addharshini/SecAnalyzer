import re
from typing import List, Dict

RULES = [
    {
        "id": "SQLI_STR_CONCAT",
        "pattern": re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+\s*\w+", re.IGNORECASE | re.DOTALL),
        "description": "Possible SQL injection via string concatenation.",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "languages": ["py", "js", "ts", "go"]
    },
    {
        "id": "SQLI_EXECUTE_RAW",
        "pattern": re.compile(r"(cursor\.execute\(|db\.query\(|Exec\()", re.IGNORECASE),
        "description": "Raw SQL execution; ensure parameterization.",
        "cwe": "CWE-89",
        "severity": "MEDIUM",
        "languages": ["py", "js", "ts", "go"]
    },
    {
        "id": "XSS_REFLECTED",
        "pattern": re.compile(r"(res\.send\(|response\.write\(|document\.write\().*req\.(query|params)", re.IGNORECASE | re.DOTALL),
        "description": "Reflected XSS risk (unsanitized user input in response).",
        "cwe": "CWE-79",
        "severity": "MEDIUM",
        "languages": ["js", "ts"]
    },
    {
        "id": "CMD_INJECTION",
        "pattern": re.compile(r"(os\.system\(|subprocess\.Popen\(|exec\()", re.IGNORECASE),
        "description": "Potential command injection if input is untrusted.",
        "cwe": "CWE-78",
        "severity": "HIGH",
        "languages": ["py"]
    },
    {
        "id": "HARDCODED_SECRET",
        "pattern": re.compile(r"(api[_-]?key|secret|password)\s*=\s*['\"][A-Za-z0-9_\-\+/=]{8,}['\"]", re.IGNORECASE),
        "description": "Hardcoded secret detected.",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "languages": ["py", "js", "ts", "go"]
    },
    {
        "id": "INSECURE_DESERIALIZATION",
        "pattern": re.compile(r"(pickle\.loads\(|yaml\.load\()", re.IGNORECASE),
        "description": "Insecure deserialization can lead to RCE.",
        "cwe": "CWE-502",
        "severity": "HIGH",
        "languages": ["py"]
    },
]

def detect_findings(code: str, lang: str) -> List[Dict]:
    findings = []
    for rule in RULES:
        if lang not in rule["languages"]:
            continue
        for m in rule["pattern"].finditer(code):
            start = m.start()
            snippet = code[max(0, start-120): start+200]
            findings.append({
                "rule_id": rule["id"],
                "description": rule["description"],
                "cwe": rule["cwe"],
                "severity": rule["severity"],
                "snippet": snippet.strip()
            })
    return findings
