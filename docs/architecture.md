[Español](architecture.es.md)

# Architecture

Lastvuln CLI is designed with a modular architecture, separation of responsibilities, 
input validation, error handling, and automated tests for critical functions.

![Architecture diagram](docs/architecture_diagram.png)

Use case diagram:

![Use case diagram](docs/case_use_diagram.png)

## CLI

The interface is built using Typer and Rich to provide a clearer and more user-friendly 
experience. Typer simplifies the implementation of commands and parameters during 
development while also providing an intuitive interface for the end user.
Together with Rich, it allows information to be displayed as tables, making it easier 
to review directly from the terminal.

## Parsing

For the dependency file scanning mode, the ecosystem is automatically identified based 
on the file name. This way, the user only needs to provide the file path to start the scan.
Additionally, depending on the file type, its structure is analyzed and the relevant 
information is extracted to later query the APIs responsible for retrieving reported 
vulnerabilities for the packages and their versions.

## APIs

Ecosystem searches use the GitHub Advisory Database API, which provides access to a large 
database of reported vulnerabilities and uses CVE identifiers widely adopted in the security industry.
Package searches use the OSV API because it is focused on vulnerability queries by specific 
package versions. Additionally, it integrates with multiple vulnerability sources, including
GitHub Advisory Database and CVE.

## Cache

SQLite improves response times for user queries. If the same command is executed multiple times,
instead of making an external request that may take several seconds, the cache retrieves the 
information previously stored.

## Formatter

From all the information provided by both APIs, only the relevant data is selected to build the 
final object. This object is then used either to generate the table displayed through Rich or to 
create export files in the supported formats (HTML, JSON, CSV, and Excel).

