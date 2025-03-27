import json
import os
import subprocess

def create_github_issue(title, body):
    try:
        subprocess.run(
            ['gh', 'issue', 'create', '--title', title, '--body', body],
            check=True
        )
        print(f"Issue created: {title}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create issue: {title}\n{e}")

# === SAST: SonarCloud ===
try:
    with open("sonar_issues.json", "r") as f:
        sonar_data = json.load(f)

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
            create_github_issue(title, body)

except Exception as e:
    print("⚠️ Failed to process SonarCloud report:", e)

# === DAST: StackHawk ===
try:
    with open("hawk/output/stackhawk-report.json", "r") as f:
        hawk_data = json.load(f)

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
            create_github_issue(title, body)

except Exception as e:
    print("⚠️ Failed to process StackHawk report:", e)
