"""Command line interface for dfir-triage."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .collector import build_report

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect local, read-only triage evidence into JSON.")
    parser.add_argument("target", type=Path, help="File or directory to inspect")
    parser.add_argument("--output", type=Path, default=Path("triage-report.json"), help="JSON report path")
    parser.add_argument("--max-files", type=int, default=500, help="Maximum files to scan (default: 500)")
    parser.add_argument("--processes", action="store_true", help="Include a live process snapshot when psutil is installed")
    return parser

def main() -> int:
    args = build_parser().parse_args()
    if args.max_files < 1:
        raise SystemExit("--max-files must be at least 1")
    report = build_report(args.target, args.max_files, args.processes)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Wrote {args.output} ({report['summary']['files_examined']} files examined)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
