import json
import os

# Ensure 'reports/' directory exists
os.makedirs("reports", exist_ok=True)

# Read SonarCloud JSON file
with open("sonar_issues.json", "r") as file:
    data = json.load(file)

vulnerabilities = []
for issue in data.get("issues", []):
    vulnerabilities.append({
        "rule": issue["rule"],
        "component": issue["component"],
        "severity": issue["severity"]
    })

# Save extracted CVE vulnerabilities to a JSON file
with open("reports/sonarqube_cve_mapped.json", "w") as output:
    json.dump(vulnerabilities, output, indent=4)

print("✅ CVE-mapped vulnerabilities saved successfully!")
