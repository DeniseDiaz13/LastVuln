import pytest
from lastvuln_cli.clean_inputs import clean_input


def test_clean_input_lowercase():
    eco = clean_input("Nuget")
    assert eco == "NUGET"


def test_clean_input_strip_spaces():
    eco = clean_input("NuGet")
    assert eco == "NUGET"

def test_clean_input_empty():
    with pytest.raises(ValueError):
        clean_input(" ")
