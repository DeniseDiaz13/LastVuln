import pytest
from lastvuln_cli.validate_inputs import validate_inputs
from lastvuln_cli.client import (
    build_month_range,
    search_for_ecosystem,
    search_for_package,
)


def test_invalid_month():
    with pytest.raises(ValueError) as exc:
        validate_inputs("pip", 2024, 13, "low", None, None, "json")

    assert "month" in str(exc.value).lower()


def test_invalid_year():
    with pytest.raises(ValueError):
        validate_inputs("pip", 1800, 5, "high", None, None, "csv")


def test_invalid_ecosystem():
    with pytest.raises(ValueError):
        validate_inputs("", 2024, 5, None, "json", None, None)


def test_year_without_month():
    with pytest.raises(ValueError):
        validate_inputs("pip", 2024, None, None, None, None, "md")


def test_month_without_year():
    with pytest.raises(ValueError):
        validate_inputs("pip", None, 5, None, None, None, "html")


def test_invalid_severity():
    with pytest.raises(ValueError):
        validate_inputs("pip", None, None, "six-seven", None, None, "json")


def test_invalid_export():
    with pytest.raises(ValueError):
        validate_inputs("maven", None, None, "low", None, None, "something")


def test_valid_inputs_search_per_ecosystem():
    validate_inputs("pip", 2025, 7, "critical", None, None, "json")


def test_valid_inputs_search_per_package():
    validate_inputs("pip", None, None, None, "jinja2", "3.1.4", "md")


def test_invalid_package():
    with pytest.raises(ValueError):
        validate_inputs("pip", None, None, None, "jinja$", "3.1.4", "html")


def test_invalid_version():
    with pytest.raises(ValueError):
        validate_inputs("pip", None, None, None, "jinja2", "3.1.$", None)


def test_valid_inputs_without_date():
    validate_inputs("pip", None, None, None, None, None, "html")


def test_leap_year():
    result = build_month_range(2024, 2)

    assert result == "2024-02-01..2024-02-29"


def test_non_leap_year():
    result = build_month_range(2025, 2)

    assert result == "2025-02-01..2025-02-28"


def test_search_for_ecosystem_more_than_50():
    result = search_for_ecosystem("pip", 51, None, None)

    assert result["status"] == 400
    assert result["message"] == "Records limit must be between 1 and 50"
    assert result["data"] == []


def test_search_for_package_more_than_50():
    result = search_for_package("3.1.4", "jinja2", "pip", 55)

    assert result["status"] == 400
    assert result["message"] == "Records limit must be between 1 and 50"
    assert result["data"] == []
