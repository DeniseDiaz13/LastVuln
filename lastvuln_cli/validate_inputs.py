from datetime import datetime
import re


def validate_inputs(
    ecosystem: str,
    year: int | None,
    month: int | None,
    severity: str | None,
    package: str | None,
    version: str | None,
    export: str | None,
):
    validate_input_ecosystem(ecosystem)

    if year is not None or month is not None or severity is not None:
        if package is not None:
            raise ValueError(f"[red]Package parameter is not supported with parameters year, month and severity[/red]")
        if version is not None:
            raise ValueError(f"[red]Version parameter is not supported with parameters year, month and severity[/red]")
    
    if (year is None) != (month is None):
        raise ValueError(f"[red]Year and month must be provided together[/red]")

    if year is not None:
        validate_input_year(year)

    if month is not None:
        validate_input_month(month)

    if severity is not None:
        validate_input_severity(severity)
    
    if (package is None) != (version is None):
        raise ValueError(f"[red]Package and version must be provided together[/red]")
     
    if package is not None:
        validate_input_package(package)

    if version is not None:
        validate_input_version(version)

    if export is not None:
        validate_input_export(export)


def validate_input_ecosystem(ecosystem: str):
    valid_inputs = [
        "rubygems",
        "npm",
        "pip",
        "maven",
        "nuget",
        "composer",
        "go",
        "rust",
        "erlang",
        "pub",
        "swift",
    ]

    if not ecosystem:
        raise ValueError(f"[red]Ecosystem cannot be empty[/red]")

    if ecosystem not in valid_inputs:
        raise ValueError(
            f"[red]Export {ecosystem} is not a possible value. Must be one of the following: {", ".join(valid_inputs)}[/red]"
        )


def validate_input_year(year: int):
    if year > datetime.now().year:
        raise ValueError(f"[red]Year cannot be future[/red]")

    if year < 2016:
        raise ValueError("[red]Year cannot be earlier than 2016.[/red]")


def validate_input_month(month: int):
    if month < 1 or month > 12:
        raise ValueError(f"[red]Month is invalid[/red]")


def validate_input_severity(severity: str):
    valid_inputs = ["none", "low", "medium", "high", "critical"]

    if severity not in valid_inputs:
        raise ValueError(
            f"[red]Severity {severity} is not a possible value. Must be one of the following: {", ".join(valid_inputs)}[/red]"
        )


def validate_input_package(package: str):
    if not package.strip():
        raise ValueError(f"[red]Package is required[/red]")

    if " " in package:
        raise ValueError(f"[red]Package name cannot contain spaces[/red]")

    if not re.fullmatch(r"[A-Za-z0-9._/@+-]+", package):
        raise ValueError(f"[red]Invalid package name[/red]")


def validate_input_version(version: str):
    if not version.strip():
        raise ValueError(f"[red]Version is required[/red]")

    if " " in version:
        raise ValueError(f"[red]Version cannot contain spaces[/red]")

    if not re.fullmatch(r"[A-Za-z0-9._+\-]+", version):
        raise ValueError(f"[red]Invalid version[/red]")


def validate_input_export(export: str):
    valid_inputs = ["json", "html", "csv", "xlsx", "md"]

    if export not in valid_inputs:
        raise ValueError(
            f"[red]Export {export} is not a possible value. Must be one of the following: {", ".join(valid_inputs)}[/red]"
        )
