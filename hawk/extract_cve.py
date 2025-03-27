import json
import os

# Ensure output directory exists
os.makedirs("reports", exist_ok=True)

# === SAST: SonarCloud ===
try:
    with open("sonar_issues.json", "r") as f:
        sonar_data = json.load(f)

    sonar_vulns = []
    for issue in sonar_data.get("issues", []):
        cve_tags = [tag for tag in issue.get("tags", []) if tag.lower().startswith("cve-")]
        if cve_tags:
            sonar_vulns.append(
                f"- **Rule**: {issue['rule']}\n  - **Component**: {issue['component']}\n  - **Severity**: {issue['severity']}\n  - **CVE Tags**: {', '.join(cve_tags)}"
            )

    with open("reports/sonarqube_cve_report.md", "w") as f:
        if sonar_vulns:
            f.write("## 🛑 SonarCloud CVE Report\n\n" + "\n\n".join(sonar_vulns))
        else:
            f.write("✅ No CVE-mapped vulnerabilities found in SAST (SonarCloud).")

    print("✅ SonarCloud CVE report generated.")
except Exception as e:
    print("⚠️ Failed to process SonarCloud report:", e)

# === DAST: StackHawk ===
try:
    with open("hawk/output/stackhawk-report.json", "r") as f:
        hawk_data = json.load(f)

    hawk_vulns = []
    for finding in hawk_data.get("findings", []):
        cve_ids = finding.get("cve", [])
        if cve_ids:
            hawk_vulns.append(
                f"- **ID**: {finding['id']}\n  - **Severity**: {finding['severity']}\n  - **Path**: {finding.get('path', 'N/A')}\n  - **CVE Tags**: {', '.join(cve_ids)}"
            )

    with open("reports/stackhawk_cve_report.md", "w") as f:
        if hawk_vulns:
            f.write("## 🛡️ StackHawk CVE Report\n\n" + "\n\n".join(hawk_vulns))
        else:
            f.write("✅ No CVE-mapped vulnerabilities found in DAST (StackHawk).")

    print("✅ StackHawk CVE report generated.")
except Exception as e:
    print("⚠️ Failed to process StackHawk report:", e)
