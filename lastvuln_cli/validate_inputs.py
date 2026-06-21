from datetime import datetime


def validate_inputs(ecosystem: str, year: int | None, month: int | None, severity: str | None, export: str | None):
    validate_input_ecosystem(ecosystem)

    if (year is None) != (month is None):
        raise ValueError(f"[red]Year and month must be provided together[/red]")

    if year is not None:
        validate_input_year(year)

    if month is not None:
        validate_input_month(month)

    if severity is not None:
        validate_input_severity(severity)

    if export is not None:
        validate_input_export(export)


def validate_input_ecosystem(ecosystem: str):
    if not ecosystem:
        raise ValueError(f"[red]Ecosystem cannot be empty[/red]")


def validate_input_year(year: int):
    if year > datetime.now().year or year < 2016:
        raise ValueError(f"[red]Year cannot be future[/red]")


def validate_input_month(month: int):
    if month < 1 or month > 12:
        raise ValueError(f"[red]Month is invalid[/red]")


def validate_input_severity(severity: str):
    valid_inputs = ["none", "low", "medium", "high", "critical"]

    if severity not in valid_inputs:
        raise ValueError(f"[red]Severity {severity} is not a possible value. Must be one of the following: {", ".join(valid_inputs)}[/red]")


def validate_input_export(export: str):
    valid_inputs = ["json", "html", "csv", "xlsx", "md"]

    if export not in valid_inputs:
        raise ValueError(f"[red]Export {export} is not a possible value. Must be one of the following: {", ".join(valid_inputs)}[/red]")

