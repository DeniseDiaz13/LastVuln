import json
import pandas as pd
from openpyxl.styles import Font
from datetime import datetime


def export_vulns(export: str, data: list[dict], filename: str):
    if export == "json":
        export_json(data, filename)
    if export == "csv":
        export_csv(data, filename)
    if export == "xlsx":
        export_excel(data, filename)
    if export == "md":
        export_markdown(data, filename)
    if export == "html":
        export_html(data, filename)


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
    headers = [k for k in data[0] if k != "summary"]

    header_line = "| " + " | ".join(headers) + " |\n"
    separator_line = "| " + " | ".join(["---"] * len(headers)) + " |\n"
    severities = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0,
    }

    rows = []
    for item in data:
        if item["published"]:
            item["published"] = item["published"][:10]
            severity = item.get("severity", "none").lower()
            if severity in severities:
                severities[severity] += 1
            else:
                severities["none"] += 1

        values = [str(item.get(header, "")) for header in headers]
        rows.append("| " + " | ".join(values) + " |\n")

    table_severities = construct_table_severities(severities)

    content = f"""# LastVuln report
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Total vulnerabilities:** {len(data)}
## Severity Summary
{table_severities}
## Vulnerabilities
{header_line}{separator_line}{''.join(rows)}
"""

    with open(f"{filename}.md", "w", encoding="utf-8") as f:
        f.write(content)


def construct_table_severities(severities: dict[str, int]) -> str:
    table = "| Severity | Count |\n" "| --- | --- |\n"

    for severity, count in severities.items():
        table += f"| {severity.upper()} | {count} |\n"

    return table


def export_html(data: list[dict], filename: str):
    headers = list(data[0].keys())
    severities = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0,
    }

    table_headers = []
    for header in headers:
        table_headers.append(
            f"<th style='background-color: #182D5D; color: white'>{header}</th>"
        )

    table_rows = []
    for row in data:
        current_cells = []

        severity = row.get("severity", "none").lower()
        if severity in severities:
            severities[severity] += 1
        else:
            severities["none"] += 1

        for header in headers:
            value = row[header]

            if header == "severity":
                current_cells.append(
                    f"<td style='background-color:{color_severity(value.upper())}; font-weight:bold;'>{value}</td>"
                )
            elif header == "score":
                current_cells.append(
                    f"<td style='background-color:{color_score(value)}; font-weight:bold;'>{value}</td>"
                )
            else:
                current_cells.append(f"<td>{value}</td>")

        row_cells = "\n            ".join(current_cells)
        table_rows.append(f"<tr>\n            {row_cells}\n        </tr>")

    cards_severities = construct_cards(severities)

    content_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LastVuln</title>
    <style>
    body {{
        font-family: Arial, sans-serif;
    }}

    table {{
        border-collapse: collapse;
        width: 100%;
    }}

    th, td {{
        padding: 8px;
        border: 1px solid #ddd;
    }}
    </style>
</head>
<body>
    <h1>LastVuln Security Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p><strong>Total vulnerabilities:</strong> {len(data)}</p>

    <div style="display: flex; gap: 1.5rem; justify-content: center; align-items: center; margin-bottom: 2rem">
        {cards_severities}
    </div>

    <table>
        <tr>
            {"\n            ".join(table_headers)} 
        </tr>
        {"\n        ".join(table_rows)}  
    </table>
</body>
</html>"""

    with open(f"{filename}.html", "w", encoding="utf-8") as archivo:
        archivo.write(content_html)


def color_severity(severity: str) -> str:
    if severity == "CRITICAL":
        return "#ff4d4f"
    elif severity == "HIGH":
        return "#ff9f43"
    elif severity == "MEDIUM":
        return "#ffd166"
    elif severity == "LOW":
        return "#4ecdc4"
    else:
        return "#b0b0b0"


def color_score(score: float) -> str:
    if score >= 0.1 and score <= 3.9:
        return "#4ecdc4"
    elif score >= 4.0 and score <= 6.9:
        return "#ffd166"
    elif score >= 7.0 and score <= 8.9:
        return "#ff9f43"
    elif score >= 9.0 and score <= 10.0:
        return "#ff4d4f"
    else:
        return "#b0b0b0"


def construct_cards(severities: dict[str, int]) -> str:
    cards = []

    for severity, count in severities.items():
        cards.append(f"""
        <div style="
          background-color: {color_severity(severity.upper())};
          border-radius: 12px; 
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04);
          padding: 1.5rem 3rem; 
          min-width: 120px;
          display: flex; 
          flex-direction: column; 
          align-items: center; 
          justify-content: center;">
          
          <p style="color: black; margin: 0; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">{severity}</p>
          <p style="color: black; margin: 0.4rem 0 0 0; font-size: 2.2rem; font-weight: bold; line-height: 1;">{count}</p>
        </div>
        """)

    return "\n".join(cards)
