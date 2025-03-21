import json
import os

# Ensure reports directory exists
os.makedirs("reports", exist_ok=True)

# Read SonarCloud JSON file
with open("sonar_issues.json", "r") as file:
    data = json.load(file)

vulnerabilities = []
for issue in data.get("issues", []):
    vulnerabilities.append(f"- **Rule**: {issue['rule']}\n  - **Component**: {issue['component']}\n  - **Severity**: {issue['severity']}")

# Save extracted CVEs to a Markdown file for GitHub Issue
issue_body = "## 🛑 SonarCloud CVE Report\n\n" + "\n".join(vulnerabilities)

with open("reports/sonarqube_cve_report.md", "w") as output:
    output.write(issue_body)

print("✅ CVE report formatted for GitHub Issues.")
