import json


def export_vulns(export: str, data: dict, filename: str):
    if export == "json":
        export_json(data, filename)


def export_json(data: dict, filename: str):
    data_json = json.dumps(data, indent = 4, ensure_ascii = False)

    with open(f"{filename}.json", "w", encoding="utf-8") as archivo:
        archivo.write(data_json)
