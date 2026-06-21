import typer
from rich.console import Console
from .cache import init_db
from .client import search_for_ecosystem
from .formatter import format_vulnerabilities
from .validate_inputs import *
from .export import *

console = Console()
app = typer.Typer()


@app.command()
def search(
    ecosystem: str = typer.Option(..., "--ecosystem", "-e"),
    n_rows: int = typer.Option(10, "--n_rows", "-n"),
    year: int | None = typer.Option(None, "--year-published", "-y"),
    month: int | None = typer.Option(None, "--month-published", "-m"),
    severity: str | None = typer.Option(None, "--severity", "-s"),
    export: str | None = typer.Option(None, "--export", "-x"),
    filename: str = typer.Option(f"vulns_export_{datetime.now():%Y-%m-%d_%H-%M-%S}", "--filename", "-f")
):
    try:
        clean_ecosystem = ecosystem.strip().lower()
        validate_inputs(clean_ecosystem, year, month, severity, export)
        data = search_for_ecosystem(clean_ecosystem, n_rows, year, month, severity)

        if data["status"] != 200:
            console.print(f"\n[red]{data['message']}[/red]")
            return

        if not data["data"]:
            console.print("\n[gray]No results found.[/gray]")
            return

        output = format_vulnerabilities(data["data"])

        if export:
            console.print(f"\n Found {len(data['data'])} results for ecosystem [cyan]{clean_ecosystem}[/cyan]\n")
            export_vulns(export, data["data"], filename)
            console.print(f"\n[green] ✓ Export completed[/green] [cyan]({filename}.{export})[/cyan]")
        else:
            console.print(f"\n Showing {len(data['data'])} results for ecosystem [cyan]{clean_ecosystem}[/cyan]\n")
            console.print(output)

    except ValueError as e:
        console.print(f"\n [red]Error:[/red] {e}")
        raise typer.Exit(code=1)


def main():
    init_db()
    app()


if __name__ == "__main__":
    main()
