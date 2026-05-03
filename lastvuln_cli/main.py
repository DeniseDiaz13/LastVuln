import typer
from rich.console import Console
from .client import search_ecosystem
from .formatter import format_vulnerabilities
from .clean_inputs import clean_input

console = Console()
app = typer.Typer()

def status(no_status: int):
    if no_status == 401:
        return f"\n [red]Invalid token.[/red]" 
    elif no_status == 422:
        return f"\n [red]Validation failed, or the endpoint has been spammed.[/red]" 
    elif no_status == 429:
        return f"\n [red]Too many requests.[/red]"
    elif no_status == 404:
        return f"\n [red]Resource not found.[/red]"

@app.command()
def search(ecosystem: str = typer.Option(..., "--ecosystem", "-e"), n_results: int = typer.Option(5, "--n_results", "-n")):
    try:
        ecosystem_clean = clean_input(ecosystem)
        data = search_ecosystem(ecosystem_clean, n_results)
        
        if isinstance(data, int):
            message = status(data)
            console.print(message)
            return

        if len(data) <= 0:
            console.print("\n [gray]No results found.[/gray]")
            return

        output = format_vulnerabilities(data)

        console.print(f"\n Showing {len(data)} results for ecosystem [cyan]{ecosystem_clean}[/cyan]\n")

        console.print(output)

    except ValueError as e:
        console.print(f"\n [red]Error:[/red] {e}")
        raise typer.Exit(code=1)



def main():
    app()


if __name__ == "__main__":
    main()
