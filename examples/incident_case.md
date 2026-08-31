# Incident Response Case: Disguised Invoice Attachment

## Scenario

An employee reports a suspicious email attachment named `Invoice_August.pdf`. The file was saved to a temporary evidence folder before being opened. Initial endpoint telemetry also shows a recently started process with the same filename.

This example demonstrates how to use the toolkit for first-pass, read-only triage. It is a fictional training case; it does not replace a full forensic acquisition or malware analysis workflow.

## Triage objective

1. Preserve a file hash for the attachment.
2. Identify whether the file content matches its apparent extension.
3. Record an explainable finding for escalation.
4. Produce a JSON report that can be attached to the incident case.

## Run the collection

```bash
dfir-triage /cases/acme-2026-08-31/evidence --output case-report.json --processes
```

## Example interpretation

If the file begins with the `MZ` header but is called `Invoice_August.pdf`, the toolkit reports a high-severity extension mismatch:

```json
{
  "path": "/cases/acme-2026-08-31/evidence/Invoice_August.pdf",
  "findings": ["PE executable header found behind a document-like extension"],
  "severity": "high"
}
```

## Analyst next steps

- Do not execute the attachment or upload it to a public service.
- Preserve the SHA-256 in the incident record and compare it with approved threat-intelligence sources.
- Review email gateway and proxy logs for the sender, recipients, download URL, and other endpoints that retrieved the file.
- Isolate affected systems according to the organization’s incident-response procedure.
- Escalate for static/dynamic malware analysis and a full evidence acquisition when indicators support it.

## What this demonstrates

The project separates collection from judgment: it records reproducible facts, states why an item was flagged, and leaves containment decisions to the incident-response process.
