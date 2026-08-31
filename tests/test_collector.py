from pathlib import Path
from dfir_triage.collector import scan_path, sha256_file
from dfir_triage.indicators import extension_mismatch, suspicious_location

def test_sha256_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("abc", encoding="utf-8")
    assert sha256_file(sample) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_extension_mismatch_detects_pe_document_decoy(tmp_path: Path) -> None:
    assert extension_mismatch(tmp_path / "invoice.pdf", b"MZ\\x90\\x00")

def test_suspicious_location_detects_temp_executable() -> None:
    assert suspicious_location(Path("/tmp/update.exe"))

def test_scan_path_collects_a_high_severity_finding(tmp_path: Path) -> None:
    decoy = tmp_path / "invoice.pdf"
    decoy.write_bytes(b"MZ\\x90\\x00payload")
    result = scan_path(tmp_path)
    assert result[0]["severity"] == "high"
    assert "PE executable" in result[0]["findings"][0]
