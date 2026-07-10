[Español](README.md)

# Lastvuln CLI

## Vulnerability search and scanner by package ecosystem

Investigate the latest published vulnerabilities and scan your dependency files.

## Why Lastvuln CLI?

When developing a project, selecting and updating packages requires maintaining a 
balance between stability, compatibility, and security. Known vulnerabilities in 
libraries can become attack vectors if they are not identified and managed in a
timely manner.

Lastvuln was born from a real need while working with a legacy web application with 
outdated packages, where an information leak occurred. Conventional analysis tools
took too long because they performed complete project scans and added multiple features 
that increased their complexity of use, in addition to the resources required for their 
execution.

Additionally, although code editors could detect vulnerabilities in some packages, the 
information provided was not always enough to make quick decisions.
For this reason, the idea of creating a lightweight tool emerged, focused on obtaining 
relevant vulnerability information from packages and facilitating technical decision-making.

## Features

- **Search ecosystem:** Displays the latest vulnerabilities from a specific ecosystem, ordered by publication date.
- **Search package:** Displays the latest vulnerabilities from a specific package, ordered by publication date.
- **Scan dependency files:** Scans dependency files.
- Integration with OSV API.
- Integration with GitHub Advisory Database.
- Local SQLite cache.
- Exporting to Markdown, HTML, JSON, CSV, and Excel.

### Supported ecosystems for scan mode

| Ecosystem | Dependency file   |
| --------- | ----------------- |
| PyPI      | requirements.txt  |
| Maven     | pom.xml           |
| npm       | package-lock.json |

## Installation  

```bash 
git clone https://github.com/DeniseDiaz13/LastVuln.git

cd LastVuln

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

## Use

```bash
lastvuln search [OPTIONS]

lastvuln scan [OPTIONS] FILE 
```

### Params 

| Short | Long | Search type | Description |
|:---|:---|:---|:---|
| `-e` | `--ecosystem` | Ecosystem, package | Search by package ecosystem. |
| `-n` | `--n_rows` | Ecosystem, package | Number of rows displayed in console. |
| `-y` | `--year` | Ecosystem | Vulnerability publication year. |
| `-m` | `--month` | Ecosystem | Vulnerability publication month. |
| `-s` | `--severity` | Ecosystem | Vulnerability severity level. |
| `-p` | `--package` | Package | Search by package name. |
| `-v` | `--version` | Package | Package version. |
| `-x` | `--export` | Ecosystem, package | Export vulnerabilities to reports. |
| `-f` | `--filename` | Ecosystem, package | Custom export filename. |

### Examples 

```bash
lastvuln search -e pip -p jinja2 -v 3.1.4

lastvuln search -e npm -n 5 -x html

lastvuln scan requirements.txt

lastvuln scan pom.xml -x md -f report_maven
```

### Screenshots 

Search package
![Screenshot 1](docs/screenshots/screenshot_1.png) 

Search by NPM ecosystem and export to HTML format
![Screenshot 2](docs/screenshots/screenshot_2.png)
![Screenshot 3](docs/screenshots/screenshot_3.png)

Scanning a requirements.txt file
![Screenshot 4](docs/screenshots/screenshot_4.png)

Search by maven ecosystem and export to Markdown format
![Screenshot 5](docs/screenshots/screenshot_5.png)
![Screenshot 6](docs/screenshots/screenshot_6.png)

## Environment variables 

Create a GitHub personal access token and configure it in the `.env` file:

```bash
GITHUB_TOKEN="your_token"
```

## Tests  

The project includes automated tests to validate the main API client functions, error handling, 
local cache behavior, dependency file processing, and scanner logic.

![Screenshot 7](docs/screenshots/screenshot_tests.png)
