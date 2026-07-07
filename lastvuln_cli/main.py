import typer
from rich.console import Console
from .cache import init_db
from .client import search_for_ecosystem, search_for_package
from .formatter import format_vulnerabilities
from .validate_inputs import *
from .export import *

console = Console()
app = typer.Typer()


@app.command()
def search(
    ecosystem: str = typer.Option(..., "--ecosystem", "-e"),
    package: str = typer.Option(None, "--package", "-p"),
    version: str = typer.Option(None, "--version", "-v"),
    n_rows: int = typer.Option(10, "--n_rows", "-n"),
    year: int | None = typer.Option(None, "--year-published", "-y"),
    month: int | None = typer.Option(None, "--month-published", "-m"),
    severity: str | None = typer.Option(None, "--severity", "-s"),
    export: str | None = typer.Option(None, "--export", "-x"),
    filename: str | None = typer.Option(None, "--filename", "-f")
):
    try:
        clean_ecosystem = ecosystem.strip().lower()
        validate_inputs(clean_ecosystem, year, month, severity, package, version, export)
        data = []

        if package:
            data = search_for_package(version, package, ecosystem, n_rows)
        else:
            data = search_for_ecosystem(clean_ecosystem, n_rows, year, month, severity)

        if data["status"] != 200:
            console.print(f"\n[red]{data['message']}[/red]")
            return

        if not data["data"]:
            console.print("\n[gray]No results found.[/gray]")
            return

        output = format_vulnerabilities(data["data"])

        if export:
            console.print(f"\n Found {len(data['data'])} results for {'package' if package else 'ecosystem'} [cyan]{package if package else clean_ecosystem}[/cyan]\n")
            
            if filename is None:
                filename = f"vulns_export_{datetime.now():%Y-%m-%d_%H-%M-%S}"

            try:
                export_vulns(export, data["data"], filename)
            except Exception as e:
                console.print(f"[red]Export failed:[/red] {e}")
                raise typer.Exit(1)
            
            console.print(f"\n[green] ✓ Export completed[/green] [cyan]({filename}.{export})[/cyan]")
        else:
            console.print(f"\n Showing {len(data['data'])} results for {'package' if package else 'ecosystem'} [cyan]{package if package else clean_ecosystem}[/cyan]\n")
            console.print(output)

    except ValueError as e:
        console.print(f"\n [red]Error:[/red] {e}")
        raise typer.Exit(code=1)


def main():
    init_db()
    app()


if __name__ == "__main__":
    main()
