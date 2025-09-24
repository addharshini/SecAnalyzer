import os
from typing import List

CODE_EXTS = {'.py', '.js', '.ts', '.go'}

def list_code_files(path: str) -> List[str]:
    files = []
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in CODE_EXTS:
            return [path]
        return []
    for root, _, filenames in os.walk(path):
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in CODE_EXTS:
                files.append(os.path.join(root, fn))
    return files

def read_file(path: str, max_bytes: int = 30000) -> str:
    with open(path, 'rb') as f:
        data = f.read(max_bytes)
    try:
        return data.decode('utf-8', errors='replace')
    except Exception:
        return data.decode('latin-1', errors='replace')
