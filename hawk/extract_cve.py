import json
import os
import subprocess
import glob

# Ensure reports folder exists
os.makedirs("reports", exist_ok=True)

def create_github_issue(title, body):
    try:
        subprocess.run(
            ['gh', 'issue', 'create', '--title', title, '--body', body],
            check=True
        )
        print(f"✅ Created GitHub Issue: {title}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create GitHub issue: {title}\n{e}")

# === SAST: SonarCloud ===
try:
    with open("sonar_issues.json", "r") as f:
        sonar_data = json.load(f)

    sonar_report = []
    for issue in sonar_data.get("issues", []):
        cve_tags = [tag for tag in issue.get("tags", []) if tag.lower().startswith("cve-")]
        if cve_tags:
            title = f"🛑 SonarCloud CVE: {', '.join(cve_tags)}"
            body = (
                f"**Rule**: {issue['rule']}\n"
                f"**Component**: {issue['component']}\n"
                f"**Severity**: {issue['severity']}\n"
                f"**CVE Tags**: {', '.join(cve_tags)}"
            )
            sonar_report.append(f"### {title}\n{body}")
            create_github_issue(title, body)

    if sonar_report:
        with open("reports/sonarcloud_cve_report.md", "w") as f:
            f.write("# 🛑 SonarCloud CVE Report\n\n" + "\n\n".join(sonar_report))

except Exception as e:
    print("⚠️ Failed to process SonarCloud report:", e)

# === DAST: StackHawk ===
try:
    stackhawk_json = glob.glob("**/stackhawk-report.json", recursive=True)
    if not stackhawk_json:
        raise FileNotFoundError("❌ StackHawk report not found.")
    
    with open(stackhawk_json[0], "r") as f:
        hawk_data = json.load(f)

    hawk_report = []
    for finding in hawk_data.get("findings", []):
        cve_ids = finding.get("cve", [])
        if cve_ids:
            title = f"🛡️ StackHawk CVE: {', '.join(cve_ids)}"
            body = (
                f"**ID**: {finding['id']}\n"
                f"**Severity**: {finding['severity']}\n"
                f"**Path**: {finding.get('path', 'N/A')}\n"
                f"**CVE Tags**: {', '.join(cve_ids)}"
            )
            hawk_report.append(f"### {title}\n{body}")
            create_github_issue(title, body)

    if hawk_report:
        with open("reports/stackhawk_cve_report.md", "w") as f:
            f.write("# 🛡️ StackHawk CVE Report\n\n" + "\n\n".join(hawk_report))

except Exception as e:
    print("⚠️ Failed to process StackHawk report:", e)
