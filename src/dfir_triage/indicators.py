"""Small, explainable heuristic checks used by the triage collector."""
from __future__ import annotations
from pathlib import Path

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".app"}
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}

def extension_mismatch(path: Path, header: bytes) -> str | None:
    """Return an explanation when an executable header masquerades as a document."""
    if path.suffix.lower() not in DECOY_EXTENSIONS:
        return None
    if header.startswith(b"MZ"):
        return "PE executable header found behind a document-like extension"
    if header.startswith(b"#!"):
        return "Script shebang found behind a document-like extension"
    return None

def suspicious_location(path: Path) -> str | None:
    """Flag executables placed in common temporary or user-download locations."""
    normalized = str(path).replace("\\", "/").lower()
    if path.suffix.lower() not in EXECUTABLE_EXTENSIONS:
        return None
    for fragment in ("/tmp/", "/temp/", "/downloads/", "/appdata/local/"):
        if fragment in normalized:
            return f"Executable located in a high-risk directory ({fragment.strip('/')})"
    return None
