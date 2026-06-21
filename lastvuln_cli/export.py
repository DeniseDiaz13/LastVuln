import json
from types import SimpleNamespace
import pandas as pd
from openpyxl.styles import Font


def export_vulns(export: str, data: list[dict], filename: str):
    if export == "json":
        export_json(data, filename)
    if export == "csv":
        export_csv(data, filename)
    if export == "xlsx":
        export_excel(data, filename)
    if export == "md":
        export_markdown(data, filename)


def export_json(data: list[dict], filename: str):
    data_json = json.dumps(data, indent=4, ensure_ascii=False)

    with open(f"{filename}.json", "w", encoding="utf-8") as archivo:
        archivo.write(data_json)


def export_csv(data: list[dict], filename: str):
    df = pd.DataFrame(data)
    df.to_csv(f"{filename}.csv", index=False)


def export_excel(data: list[dict], filename: str):
    df = pd.DataFrame(data)

    with pd.ExcelWriter(f"{filename}.xlsx", engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Sheet1")

        ws = writer.sheets["Sheet1"]

        for cell in ws[1]:
            cell.font = Font(bold=True)


def export_markdown(data: list[dict], filename: str):
    headers = list(data[0].keys())
    header_line = "| " + " | ".join(headers) + " |\n"
    separator_line = "| " + " | ".join(["---"] * len(headers)) + " |\n"

    rows = []
    for item in data:
        data_object = SimpleNamespace(**item)
        values = [str(getattr(data_object, header, "")) for header in headers]
        rows.append("| " + " | ".join(values) + " |\n")
    
    with open(f"{filename}.md", "w", encoding="utf-8") as f:
        f.write(header_line)
        f.write(separator_line)
        f.writelines(rows)

