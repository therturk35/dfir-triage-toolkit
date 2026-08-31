# DFIR Triage Toolkit

A small, local-first command-line tool for collecting explainable, read-only triage evidence during an incident response investigation.

Built as a cybersecurity portfolio project by [Tugce Erturk](https://github.com/therturk35), with an emphasis on defensible collection, evidence integrity, and clear reporting.

## What it does

- Calculates a SHA-256 hash for every inspected file.
- Captures file size and UTC modification time.
- Detects PE executable (`MZ`) and script-shebang headers hidden behind document-like extensions.
- Flags executables running from common high-risk locations such as `tmp`, `temp`, `Downloads`, and `AppData/Local`.
- Produces a structured JSON report suitable for review or ingestion into another tool.
- Optionally captures a lightweight live-process snapshot using `psutil`.

The toolkit is intentionally read-only: it does not quarantine, delete, upload, or alter scanned files.

## Quick start

```bash
git clone https://github.com/therturk35/dfir-triage-toolkit.git
cd dfir-triage-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
dfir-triage /path/to/evidence --output case-report.json
```

To capture processes as well:

```bash
pip install -e ".[processes]"
dfir-triage /path/to/evidence --processes --output case-report.json
```

## Example finding

```json
{
  "path": "/evidence/invoice.pdf",
  "sha256": "…",
  "findings": ["PE executable header found behind a document-like extension"],
  "severity": "high"
}
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Responsible use

Use only on systems and evidence you are authorized to inspect. Treat outputs as triage indicators, not as a conclusive malware verdict.

## Roadmap

- YARA rule support
- Case manifest with collector and tool version metadata
- CSV and Markdown summary exports
- Windows event log and browser artifact collectors

## License

MIT. See [LICENSE](LICENSE).
