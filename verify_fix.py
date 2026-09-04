"""
Verification script for the _replace_fortinet_set regex fix.

Demonstrates that:
1. The fix prevents cross-line merging corruption.
2. Only findings genuinely affected by the allowaccess change are resolved.
3. Unrelated findings (SNMP, timeout, SSH, banner, boundary, logging, crypto)
   are NOT incorrectly reported as resolved.
"""

import sys, os, pathlib

# Add backend to path so we can import app modules
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "backend"))

from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze
from app.remediation.engine import generate_remediation, apply_remediation


def main():
    # -- 1. Load the fixture ---------------------------------------------------
    fixture = pathlib.Path(__file__).resolve().parent / "backend" / "tests" / "fixtures" / "fortinet_vulnerable.cfg"
    if not fixture.exists():
        fixture = pathlib.Path(__file__).resolve().parent / "sample" / "frontinet" / "fortinet_demo_vulnerable.cfg"
    if not fixture.exists():
        print("ERROR: Cannot find fortinet vulnerable config fixture.")
        sys.exit(1)

    raw = fixture.read_text()
    print(f"Loaded config from: {fixture}\n")

    # -- 2. Parse and run initial analysis -------------------------------------
    parser = FortinetParser()
    config = parser.parse(raw)
    initial_result = analyze(config)

    initial_ids = sorted(set(f.rule_id for f in initial_result.findings))
    print(f"Initial findings ({len(initial_result.findings)}): {initial_ids}\n")

    # -- 3. Find MGMT-001 and generate remediation -----------------------------
    mgmt001 = [f for f in initial_result.findings if f.rule_id == "MGMT-001"]
    if not mgmt001:
        print("ERROR: MGMT-001 not found in initial analysis.")
        sys.exit(1)

    finding = mgmt001[0]
    remediation = generate_remediation(finding, [config])
    print(f"MGMT-001 remediation commands:\n{remediation['commands']}\n")

    # -- 4. Apply remediation --------------------------------------------------
    modified_config = apply_remediation(config, remediation["commands"])

    # -- 5. Check line integrity -----------------------------------------------
    print("=" * 60)
    print("LINE INTEGRITY CHECK")
    print("=" * 60)

    lines = modified_config.raw_config.splitlines()
    ip_line = None
    allowaccess_line = None
    for i, line in enumerate(lines):
        if "set ip " in line and "203.0.113" in line:
            ip_line = (i + 1, line)
        if "set allowaccess" in line and ip_line and not allowaccess_line:
            allowaccess_line = (i + 1, line)

    if ip_line:
        print(f"  Line {ip_line[0]}: {ip_line[1].strip()}")
    if allowaccess_line:
        print(f"  Line {allowaccess_line[0]}: {allowaccess_line[1].strip()}")

    if ip_line and allowaccess_line and ip_line[0] != allowaccess_line[0]:
        print("\n  [PASS] 'set ip' and 'set allowaccess' are on SEPARATE lines.")
    else:
        print("\n  [FAIL] Lines are merged or missing!")
        sys.exit(1)

    # Also verify no line contains both "set ip" and "set allowaccess"
    for i, line in enumerate(lines):
        if "set ip " in line and "set allowaccess" in line:
            print(f"  [FAIL] Line {i+1} contains BOTH 'set ip' and 'set allowaccess' -- corruption!")
            sys.exit(1)
    print("  [PASS] No single line contains both directives.\n")

    # -- 6. Re-analyze and compare ---------------------------------------------
    post_result = analyze(modified_config)
    post_ids = set(f.rule_id for f in post_result.findings)

    resolved = set(initial_ids) - post_ids
    remaining = sorted(post_ids)

    print("=" * 60)
    print("FINDING COMPARISON")
    print("=" * 60)
    print(f"  Initial findings: {initial_ids}")
    print(f"  Post-fix findings: {remaining}")
    print(f"  Resolved:  {sorted(resolved)}")
    print()

    # -- 7. Validate which findings SHOULD be resolved -------------------------
    # MGMT-001 (telnet on wan): telnet removed from allowaccess -> RESOLVED
    # MGMT-002 (http on wan):   http removed from allowaccess   -> RESOLVED
    # MGMT-003 (unrestricted mgmt on wan): ssh+https still allowed on wan,
    #   but the MGMT-003 rule checks for any mgmt service (ssh, https, http,
    #   telnet) on WAN interfaces.  The remediation sets allowaccess to
    #   "ping https ssh" -- so ssh and https are still present on wan1.
    #   MGMT-003 should therefore STILL be flagged (NOT resolved).
    #   However, the MGMT-001 remediation template only removes telnet;
    #   let's check what actually happens.

    # Definitely should NOT be resolved:
    unrelated = {"MGMT-004", "MGMT-006", "MGMT-007", "MGMT-009",
                 "BOUNDARY-001", "BOUNDARY-002", "BOUNDARY-003",
                 "LOG-001", "LOG-002", "CRYPTO-001"}

    falsely_resolved = resolved & unrelated
    if falsely_resolved:
        print(f"  [FAIL] Unrelated findings falsely resolved: {sorted(falsely_resolved)}")
        sys.exit(1)
    else:
        print("  [PASS] No unrelated findings were falsely resolved.")

    # Explain each resolved finding
    print()
    for rid in sorted(resolved):
        if rid == "MGMT-001":
            print(f"  {rid}: RESOLVED -- telnet removed from allowaccess (legitimate fix)")
        elif rid == "MGMT-002":
            print(f"  {rid}: RESOLVED -- http removed from allowaccess (legitimate fix,")
            print(f"         template sets 'ping https ssh' which drops http)")
        elif rid == "MGMT-003":
            print(f"  {rid}: RESOLVED -- check management.py: rule fires when ANY of")
            print(f"         {{ssh, https, http, telnet}} is on a WAN interface.")
            print(f"         After remediation allowaccess='ping https ssh', ssh+https")
            print(f"         are still present -> this should still fire unless the")
            print(f"         MGMT-003 template (which sets allowaccess to 'ping' only)")
            print(f"         was also applied. Verify if this is expected.")
        else:
            print(f"  {rid}: RESOLVED -- review if this is legitimate")

    print()
    print("=" * 60)
    print("VERIFICATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
