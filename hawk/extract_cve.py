import json
import os
import subprocess

# Ensure output directory exists
os.makedirs("reports", exist_ok=True)

def create_github_issue(title, body):
    try:
        subprocess.run([
            "gh", "issue", "create",
            "--title", title,
            "--body", body
        ], check=True)
        print(f"✅ Created GitHub Issue: {title}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create GitHub issue for {title}:", e)

# === SAST: SonarCloud ===
try:
    with open("sonar_issues.json", "r") as f:
        sonar_data = json.load(f)

    issues = sonar_data.get("issues", [])
    if issues:
        report = "## 🛑 SonarCloud CVE Report\n\n"
        for issue in issues:
            cve_tags = [tag for tag in issue.get("tags", []) if tag.lower().startswith("cve-")]
            if not cve_tags:
                continue
            report += (
                f"### 🔹 Rule: `{issue['rule']}`\n"
                f"- **Component**: `{issue['component']}`\n"
                f"- **Severity**: `{issue['severity']}`\n"
                f"- **CVE Tags**: {', '.join(cve_tags)}\n"
                f"- **Link**: [View on SonarCloud](https://sonarcloud.io/project/issues?id=Dubeyshagun29_HCL_Demo&open={issue['key']})\n\n"
            )
        create_github_issue("🛑 SonarCloud CVE Report", report)
    else:
        create_github_issue("🛑 SonarCloud CVE Report", "✅ No CVE-mapped vulnerabilities found in SAST (SonarCloud).")
except Exception as e:
    print("⚠️ Failed to process SonarCloud report:", e)

# === DAST: StackHawk ===
try:
    with open("hawk/output/stackhawk-report.json", "r") as f:
        hawk_data = json.load(f)

    findings = hawk_data.get("findings", [])
    if findings:
        report = "## 🛡️ StackHawk CVE Report\n\n"
        for finding in findings:
            cve_ids = finding.get("cve", [])
            if not cve_ids:
                continue
            report += (
                f"### 🔸 ID: `{finding['id']}`\n"
                f"- **Severity**: `{finding['severity']}`\n"
                f"- **Path**: `{finding.get('path', 'N/A')}`\n"
                f"- **CVE Tags**: {', '.join(cve_ids)}\n\n"
            )
        create_github_issue("🛡️ StackHawk CVE Report", report)
    else:
        create_github_issue("🛡️ StackHawk CVE Report", "✅ No CVE-mapped vulnerabilities found in DAST (StackHawk).")
except Exception as e:
    print("⚠️ Failed to process StackHawk report:", e)
