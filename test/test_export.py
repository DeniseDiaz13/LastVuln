import json
from lastvuln_cli.export import *


def test_export_json(tmp_path):
    data = [
        {
            "package": "requests",
            "severity": "high",
        }
    ]

    filename = tmp_path / "vulns"

    export_json(data, str(filename))

    exported_file = tmp_path / "vulns.json"

    assert exported_file.exists()

    exported_data = json.loads(exported_file.read_text(encoding="utf-8"))

    assert exported_data == data


def test_export_json_empty(tmp_path):
    filename = tmp_path / "empty"

    export_json([], str(filename))

    exported_file = tmp_path / "empty.json"

    assert exported_file.exists()

    exported_data = json.loads(exported_file.read_text())

    assert exported_data == []


def test_export_csv(tmp_path):
    data = [
        {
            "package": "requests",
            "severity": "high",
        }
    ]

    filename = tmp_path / "vulns"

    export_csv(data, str(filename))

    exported_file = tmp_path / "vulns.csv"

    assert exported_file.exists()

    exported_data = pd.read_csv(exported_file)

    assert exported_data.to_dict(orient="records") == data


def test_export_csv_empty(tmp_path):
    filename = tmp_path / "empty"

    export_csv([], str(filename))

    exported_file = tmp_path / "empty.csv"

    assert not exported_file.exists()


def test_export_xlsx(tmp_path):
    data = [
        {
            "package": "requests",
            "severity": "high",
        }
    ]

    filename = tmp_path / "vulns"

    export_excel(data, str(filename))

    exported_file = tmp_path / "vulns.xlsx"

    assert exported_file.exists()

    exported_data = pd.read_excel(exported_file)

    assert exported_data.to_dict(orient="records") == data


def test_export_xlsx_empty(tmp_path):
    filename = tmp_path / "empty"

    export_excel([], str(filename))

    exported_file = tmp_path / "empty.xlsx"

    assert not exported_file.exists()


def test_export_markdown(tmp_path):
    data = [
        {
            "package": "requests",
            "severity": "high",
            "score": 8.2,
            "epss": 10.5,
            "affected_versions": "<2.0",
            "fixed_version": "2.0",
            "published": "2026-06-21T15:30:00Z",
            "cve_id": "CVE-2026-1234",
            "cwe_id": "CWE-79",
            "ghsa_id": "GHSA-xxxx-yyyy",
            "summary": "Example vulnerability",
        }
    ]

    filename = tmp_path / "vulns"

    export_markdown(data, str(filename))

    exported_file = tmp_path / "vulns.md"

    assert exported_file.exists()

    content = exported_file.read_text(encoding="utf-8")

    assert "# LastVuln report" in content
    assert "## Severity Summary" in content
    assert "## Vulnerabilities" in content
    assert "| package | severity |" in content
    assert "| HIGH | 1 |" in content
    assert "requests" in content
    assert "2026-06-21" in content


def test_export_markdown_empty(tmp_path):
    filename = tmp_path / "empty"

    export_markdown([], str(filename))

    exported_file = tmp_path / "empty.md"

    assert not exported_file.exists()


def test_export_html(tmp_path):
    data = [
        {
            "package": "requests",
            "severity": "high",
            "score": 8.2,
            "epss": 10.5,
            "affected_versions": "<2.0",
            "fixed_version": "2.0",
            "published": "2026-06-21T15:30:00Z",
            "cve_id": "CVE-2026-1234",
            "cwe_id": "CWE-79",
            "ghsa_id": "GHSA-xxxx-yyyy",
            "summary": "Example vulnerability",
        }
    ]

    filename = tmp_path / "report"

    export_html(data, str(filename))

    exported_file = tmp_path / "report.html"

    assert exported_file.exists()

    content = exported_file.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in content
    assert "<title>LastVuln</title>" in content
    assert "LastVuln Security Report" in content
    assert "Total vulnerabilities:</strong> 1" in content
    assert "requests" in content
    assert "high" in content
    assert "CVE-2026-1234" in content
    assert "<table>" in content
    assert "</table>" in content


def test_export_html_empty(tmp_path):
    filename = tmp_path / "empty"

    export_html([], str(filename))

    exported_file = tmp_path / "empty.html"

    assert not exported_file.exists()
