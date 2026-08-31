"""Evidence collection primitives. They never modify the scanned target."""
from __future__ import annotations
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from .indicators import extension_mismatch, suspicious_location

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def scan_path(target: Path, max_files: int = 500) -> list[dict[str, Any]]:
    """Collect metadata and transparent heuristic findings for files below target."""
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    candidates = [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file())
    records: list[dict[str, Any]] = []
    for path in candidates[:max_files]:
        try:
            stat = path.stat()
            with path.open("rb") as source:
                header = source.read(32)
            findings = [item for item in (extension_mismatch(path, header), suspicious_location(path)) if item]
            records.append({"path": str(path.resolve()), "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                "sha256": sha256_file(path), "findings": findings,
                "severity": "high" if findings else "informational"})
        except (OSError, PermissionError) as error:
            records.append({"path": str(path), "error": str(error), "severity": "unavailable"})
    return records

def process_snapshot() -> list[dict[str, Any]]:
    """Return a minimal live-process snapshot when optional psutil is installed."""
    try:
        import psutil
    except ImportError:
        return [{"note": "Install with \`pip install .[processes]\` to collect live processes."}]
    rows = []
    for process in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
        try:
            info = process.info
            executable = info.get("exe") or ""
            rows.append({"pid": info["pid"], "name": info.get("name"), "executable": executable,
                "rss_bytes": getattr(info.get("memory_info"), "rss", None),
                "suspicious_location": suspicious_location(Path(executable)) if executable else None})
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return rows

def build_report(target: Path, max_files: int, include_processes: bool) -> dict[str, Any]:
    files = scan_path(target, max_files=max_files)
    return {"report_version": "0.1.0", "generated_at": datetime.now(UTC).isoformat(),
        "host": {"hostname": os.uname().nodename if hasattr(os, "uname") else "unknown"},
        "scope": {"target": str(target.resolve()), "max_files": max_files},
        "summary": {"files_examined": len(files), "files_with_findings": sum(bool(row.get("findings")) for row in files)},
        "files": files, "processes": process_snapshot() if include_processes else []}
