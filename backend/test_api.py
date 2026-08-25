"""Quick test of the scan API endpoint."""
import httpx

with open("tests/fixtures/cisco_vulnerable.cfg", "rb") as f:
    r = httpx.post(
        "http://localhost:8000/api/scan",
        files=[("files", ("cisco_vulnerable.cfg", f, "text/plain"))],
        timeout=30,
    )

data = r.json()
score = data["score"]
total = data["total_findings"]
crit = data["critical"]
high = data["high"]
med = data["medium"]
low = data["low"]
scan_id = data["scan_id"]

print(f"Status: {r.status_code}")
print(f"Score: {score}/100")
print(f"Total findings: {total}")
print(f"Critical: {crit}, High: {high}, Medium: {med}, Low: {low}")
print(f"Scan ID: {scan_id}")
print()
for finding in data["findings"]:
    sev = finding["severity"].upper()
    print(f"  [{sev:>8}] {finding['rule_id']}: {finding['title']}")
