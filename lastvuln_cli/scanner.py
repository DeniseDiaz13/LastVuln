from .client import consult_per_package, fetch_ghsa_ids, format_data
import xml.etree.ElementTree as ET
import json


def get_ecosystem(path) -> str | None:
    file_name = path.name

    if file_name == "requirements.txt":
        return "pip"
    elif file_name == "pom.xml":
        return "maven"
    elif file_name == "package-lock.json":
        return "npm"


def get_packages_pip(path):
    with open(path, "r", encoding="utf-8") as archive:
        content = archive.read()

    packages = {}

    for line in content.split("\n"):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        line = line.split("#", 1)[0].strip()

        if "==" in line:
            name, version = line.split("==", 1)
            packages[name] = version

    return packages


def get_packages_maven(path):
    tree = ET.parse(path)
    root = tree.getroot()
    namespace = ""

    if root.tag.startswith("{"):
        namespace = root.tag.split("}")[0].replace("{", "")

    ns = {"m": namespace} if namespace else {}

    dependencies = (root.findall("./m:dependencies/m:dependency", ns) if namespace else root.findall(".//dependency"))

    packages = {} 
    for dependency in dependencies:
        group_id = (dependency.find("m:groupId", ns) if namespace else dependency.find("groupId"))
        artifact_id = (dependency.find("m:artifactId", ns) if namespace else dependency.find("artifactId"))
        version = (dependency.find("m:version", ns) if namespace else dependency.find("version"))

        if group_id is None or artifact_id is None or version is None:
            continue

        name = f"{group_id.text}:{artifact_id.text}"
        version = version.text
        packages[name] = version

    return packages


def get_packages_node(path):
    content = json.loads(path.read_text())

    packages = {}

    for path, info in content.get("packages", {}).items():
        if path == "":
            continue

        if "node_modules/" in path:
            name = path.removeprefix("node_modules/")
            version = info.get("version")

            if version:
                packages[name] = version

    return packages


def get_packages(path, ecosystem) -> dict[str, str]:
    packages = {}

    if ecosystem == "pip":
        packages = get_packages_pip(path)
    elif ecosystem == "maven":
        packages = get_packages_maven(path)
    elif ecosystem == "npm":
        packages = get_packages_node(path)

    return packages


def get_vulns(packages: dict[str, str], ecosystem: str):
    if not packages:
        return {
            "status": 200,
            "message": "",
            "data": [],
        }

    ids = [] 
    errors = []
    for package, version in packages.items():
        result = fetch_ghsa_ids(version, package, ecosystem)

        if result["status"] != 200:
            errors.append({
                "package": package,
                "version": version,
                "message": result["message"]
            })
            continue

        ids.extend(result["data"])    

    if not ids:
        return {
            "status": 200,
            "message": "",
            "data": [],
        }

    vulns = consult_per_package(ids)

    if vulns["status"] != 200:
        return {
            "status": vulns["status"],
            "message": vulns["message"] or "Unknown error",
            "data": [],
            "errors": errors
        }

    data_clean = format_data(vulns)

    return data_clean
