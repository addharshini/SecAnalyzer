import os
from typing import Optional, Dict

def get_provider() -> str:
    return os.getenv("LLM_PROVIDER", "none").lower()

def suggest_fix(code_snippet: str, cwe_id: str, description: str) -> Optional[str]:
    provider = get_provider()
    if provider == "none":
        return None

    prompt = f"""You are an expert application security engineer.
    A code snippet likely contains a vulnerability.

    CWE: {cwe_id}
    Issue: {description}

    Code:
    ```
    {code_snippet}
    ```

    Task:
    1) Explain the risk in one paragraph.
    2) Provide a secure rewrite of the code.
    3) Mention relevant secure patterns (parameterized queries, output encoding, etc.).
    """

    # NOTE: For portability, we do not make network calls here.
    # Replace the return below with your preferred LLM SDK call.
    return (f"[LLM({provider}) suggestion placeholder]\n"
            f"Prompt used:\n{prompt[:500]}...\n"
            "Explanation: ...\nSecure Fix:\n```\n// patched code here\n```\nBest practices: ...")

def enrich_with_llm(finding: Dict) -> Dict:
    suggestion = suggest_fix(
        code_snippet=finding.get("snippet", ""),
        cwe_id=finding.get("cwe", ""),
        description=finding.get("description", ""),
    )
    if suggestion:
        finding["llm_suggestion"] = suggestion
    return finding
