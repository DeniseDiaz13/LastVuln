from rich.console import Console
from rich.table import Table
from typing import Any

console = Console()


def color_severity(severity: str) -> str:
    if severity == "CRITICAL":
        return f"[red]{severity}[/red]"
    elif severity == "HIGH":
        return f"[#ff8800]{severity}[/]"
    elif severity == "MEDIUM":
        return f"[yellow]{severity}[/yellow]"
    elif severity == "LOW":
        return f"[green]{severity}[/green]"
    else:
        return f"[gray]{severity}[/gray]"


def color_score(score: float) -> str:
    if score >= 0.1 and score <= 3.9:
        return f"[green]{score}[/green]"
    elif score >= 4.0 and score <= 6.9:
        return f"[yellow]{score}[/yellow]"
    elif score >= 7.0 and score <= 8.9:
        return f"[#ff8800]{score}[/]"
    elif score >= 9.0 and score <= 10.0:
        return f"[red]{score}[/red]"
    else:
        return f"[gray]{score}[/gray]"


def format_vulnerabilities(vulns: list[dict[str, Any]]) -> Table:
    table = Table(show_header=True, header_style="bold #A07AF0")
    table.add_column("Name Pakage", style="dim", width=20)
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("EPSS")
    table.add_column("Affected Versions")
    table.add_column("Patched Version")
    table.add_column("Published At")
    table.add_column("CVE")
    table.add_column("CWE")
    table.add_column("GHSA")
    table.add_column("Summary", width=50)

    for vuln in vulns:
        table.add_row(
            vuln.get("package", "N/A"),
            color_severity(vuln.get("severity", "N/A").upper()),
            str(color_score(vuln.get("score", "N/A"))),
            str(vuln.get("epss", "N/A")) + "%",
            vuln.get("affected_versions", "N/A"),
            vuln.get("fixed_version", "N/A"),
            vuln.get("published", "N/A")[:10],
            vuln.get("cve_id", "N/A"),
            vuln.get("cwe_id", "N/A"),
            vuln.get("ghsa_id", "N/A"),
            vuln.get("summary", "N/A"),
        )

    return table
