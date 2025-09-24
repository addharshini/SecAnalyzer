CWE_INFO = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-502": "Deserialization of Untrusted Data",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def cwe_title(cwe_id: str) -> str:
    return CWE_INFO.get(cwe_id, "Unknown CWE")

def normalize_severity(s: str) -> str:
    s = (s or "LOW").upper()
    return s if s in SEVERITY_ORDER else "LOW"

def max_severity(a: str, b: str) -> str:
    a, b = normalize_severity(a), normalize_severity(b)
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b
