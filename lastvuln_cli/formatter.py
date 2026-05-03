from rich.console import Console
from rich.table import Table

console = Console()

def color_severity(severity):
    if severity == "CRITICAL":
        return f"[red]{severity}[/red]"
    if severity == "HIGH":
        return f"[#ff8800]{severity}[/]"
    elif severity == "MODERATE":
        return f"[yellow]{severity}[/yellow]"
    elif severity == "LOW":
        return f"[green]{severity}[/green]"
    else:
        return f"[gray]{severity}[/gray]"

def format_vulnerabilities(vulns: list[dict]) -> Table:
    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("Name Pakage", style="dim", width=28)
    table.add_column("Affected Versions")
    table.add_column("Patched Version")
    table.add_column("Summary")
    table.add_column("Severity")
    table.add_column("Published At")

    for vuln in vulns:
        table.add_row(
            vuln.get("package", "N/A"),
            vuln.get("version_range", "N/A"),
            vuln.get("patched", "N/A"),
            vuln.get("summary", "N/A"),
            color_severity(vuln.get("severity", "N/A")), 
            vuln.get("published", "N/A")[:10]
        )

    return table
