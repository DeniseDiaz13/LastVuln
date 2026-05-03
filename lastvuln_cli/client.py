import requests
from dotenv import load_dotenv
import os

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise ValueError("Error token")

BASE_URL = "https://api.github.com/graphql"

query = """
query ($ecosystem: SecurityAdvisoryEcosystem!) {
  securityVulnerabilities(
    first: 20
    ecosystem: $ecosystem
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    nodes {
      package {
        name
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
      advisory {
        ghsaId
        summary
        severity
        publishedAt
        identifiers {
          type
          value
        }
      }
    }
  }
}
"""

def search_ecosystem(eco, n):
    variables = {
        "ecosystem": eco
    }

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.post(
        BASE_URL,
        json={"query": query, "variables": variables},
        headers=headers
    )

    data = response.json()
    vulns = []
    vuln_map = {}
    status = data.get("status", None)

    if status and status != "200":
        return int(status) 

    if not data or data.get("errors"):
        return []

    for vuln in data["data"]["securityVulnerabilities"]["nodes"]:
        ghsa_id = vuln["advisory"]["ghsaId"]
        pkg = vuln["package"]["name"]
        patched_info = vuln.get("firstPatchedVersion")

        if ghsa_id not in vuln_map:
            vuln_map[ghsa_id] = {
                "ghsa_id": ghsa_id,
                "package": pkg,
                "version_range": vuln["vulnerableVersionRange"],
                "patched": patched_info["identifier"] if patched_info else "N/A",
                "summary": vuln["advisory"]["summary"],
                "severity": vuln["advisory"]["severity"],
                "published": vuln["advisory"]["publishedAt"],
                "packages": []
            }

        vuln_map[ghsa_id]["packages"].append(pkg)

    vulns = list(vuln_map.values())
    
    return vulns[:n]
