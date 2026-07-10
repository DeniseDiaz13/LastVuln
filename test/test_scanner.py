from lastvuln_cli.scanner import (
    get_ecosystem,
    get_packages,
    get_packages_maven,
    get_packages_node,
    get_packages_pip,
    get_vulns,
)
from unittest.mock import patch


def test_get_ecosystem(tmp_path):
    file = tmp_path / "requirements.txt"
    file.touch()

    assert get_ecosystem(file) == "pip"


def test_get_ecosystem_invalid(tmp_path):
    file = tmp_path / "requires.txt"
    file.touch()

    assert get_ecosystem(file) == None


def test_get_packages_pip(tmp_path):
    file = tmp_path / "requirements.txt"
    file.touch()
    file.write_text("""
requests==2.31.0
flask==3.0.0
""")

    result = get_packages_pip(file)

    assert result == {"requests": "2.31.0", "flask": "3.0.0"}


def test_get_packages_pip_with_comments(tmp_path):
    file = tmp_path / "requirements.txt"
    file.touch()
    file.write_text("""
# this is a comment
requests==2.31.0 # stable version
flask==3.0.0
""")

    result = get_packages_pip(file)

    assert result == {"requests": "2.31.0", "flask": "3.0.0"}


def test_get_packages_maven(tmp_path):
    file = tmp_path / "pom.xml"
    file.touch()
    file.write_text("""
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
""")

    result = get_packages_maven(file)

    assert result == {"org.apache.logging.log4j:log4j-core": "2.14.1"}


def test_get_packages_node(tmp_path):
    file = tmp_path / "package-lock.json"

    file.write_text("""
{
    "packages": {
        "": {},
        "node_modules/lodash": {
            "version": "4.17.21"
        }
    }
}
""")

    result = get_packages_node(file)

    assert result == {"lodash": "4.17.21"}


def test_get_packages_routes_to_pip(tmp_path):
    file = tmp_path / "requirements.txt"
    file.write_text("requests==2.31.0")

    result = get_packages(file, "pip")

    assert result["requests"] == "2.31.0"


@patch("lastvuln_cli.scanner.fetch_ghsa_ids")
@patch("lastvuln_cli.scanner.consult_per_package")
@patch("lastvuln_cli.scanner.format_data")
def test_get_vulns(mock_format, mock_consult, mock_fetch):
    mock_fetch.return_value = {"status": 200, "data": ["GHSA-13"]}

    mock_consult.return_value = {"status": 200}

    mock_format.return_value = {"status": 200, "data": [{"id": "GHSA-13"}]}

    result = get_vulns({"requests": "2.13.0"}, "pip")

    assert result["data"]
    mock_fetch.assert_called_once()
    mock_consult.assert_called_once()
