# -*- coding: utf-8 -*-
"""
Remediation regression diagnostic.

For every known-vendor config, this script:
1. Parses the original config
2. Analyzes it (finds findings)
3. Generates remediation for every finding
4. Applies ALL remediation to produce a fixed config
5. Re-parses and re-analyzes the fixed config
6. Reports which findings survive and why
"""
import sys, os, copy, re

sys.path.insert(0, os.path.dirname(__file__))

from app.parsers.detector import detect_vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze
from app.analysis.scoring import calculate_score
from app.remediation.engine import generate_remediation, apply_remediation
from app.models.normalized import Vendor

# Collect all known-vendor config files
CONFIG_FILES = []
sample_dir = os.path.join(os.path.dirname(__file__), "..", "sample")
fixture_dir = os.path.join(os.path.dirname(__file__), "tests", "fixtures")

for root, dirs, files in os.walk(sample_dir):
    for f in files:
        if f.endswith(".cfg") and "unknown" not in f.lower():
            CONFIG_FILES.append(os.path.join(root, f))

for root, dirs, files in os.walk(fixture_dir):
    for f in files:
        if f.endswith(".cfg"):
            CONFIG_FILES.append(os.path.join(root, f))

print("=" * 70)
print("REMEDIATION REGRESSION DIAGNOSTIC")
print("=" * 70)
print(f"\nFound {len(CONFIG_FILES)} config files to test\n")

PASS_FILES = []
FAIL_FILES = []

for config_path in sorted(CONFIG_FILES):
    fname = os.path.basename(config_path)
    
    with open(config_path, "r") as f:
        raw_config = f.read()
    
    # Step 1: Parse
    vendor = detect_vendor(raw_config)
    if vendor == Vendor.UNKNOWN:
        print(f"  SKIP {fname}: unknown vendor")
        continue
    
    if vendor == Vendor.CISCO_IOS:
        config = CiscoIOSParser().parse(raw_config)
    elif vendor == Vendor.FORTINET:
        config = FortinetParser().parse(raw_config)
    else:
        print(f"  SKIP {fname}: unsupported vendor {vendor}")
        continue
    
    # Step 2: Analyze original
    original_result = analyze(config)
    orig_score = original_result.score
    orig_findings = original_result.findings
    
    print(f"\n{'='*70}")
    print(f"FILE: {fname}")
    print(f"  Vendor: {vendor.value}")
    print(f"  Original Score: {orig_score}/100")
    print(f"  Original Findings: {len(orig_findings)}")
    
    if not orig_findings:
        print(f"  -> No findings (already 100/100). PASS")
        PASS_FILES.append(fname)
        continue
    
    for f in orig_findings:
        print(f"    [{f.severity.value:8s}] {f.rule_id}: {f.title}")
    
    # Step 3: Generate remediation for each finding
    all_commands = []
    for finding in orig_findings:
        remediation = generate_remediation(finding, [config])
        all_commands.append(remediation["commands"])
    
    # Step 4: Apply ALL remediation (same as download-fixed endpoint)
    modified = copy.deepcopy(config)
    for commands in all_commands:
        modified = apply_remediation(modified, commands)
    
    fixed_raw = modified.raw_config
    
    # Step 5: Re-parse the fixed config from raw text (fresh parse)
    fixed_vendor = detect_vendor(fixed_raw)
    if fixed_vendor == Vendor.CISCO_IOS:
        fixed_config = CiscoIOSParser().parse(fixed_raw)
    elif fixed_vendor == Vendor.FORTINET:
        fixed_config = FortinetParser().parse(fixed_raw)
    else:
        print(f"  ERROR: Fixed config detected as {fixed_vendor}")
        FAIL_FILES.append((fname, "Vendor detection failed on fixed config"))
        continue
    
    # Step 6: Re-analyze
    fixed_result = analyze(fixed_config)
    fixed_score = fixed_result.score
    fixed_findings = fixed_result.findings
    
    print(f"\n  Fixed Score: {fixed_score}/100")
    print(f"  Fixed Findings: {len(fixed_findings)}")
    
    if fixed_findings:
        print(f"\n  SURVIVING FINDINGS:")
        for f in fixed_findings:
            print(f"    [{f.severity.value:8s}] {f.rule_id}: {f.title}")
            print(f"              Evidence: {f.evidence_lines[:2]}")
        
        # Detailed investigation for each surviving finding
        print(f"\n  ROOT CAUSE ANALYSIS:")
        for f in fixed_findings:
            print(f"\n    --- {f.rule_id}: {f.title} ---")
            
            if f.rule_id == "MGMT-001":
                print(f"    VTY lines in fixed config:")
                for vty in fixed_config.management.vty_lines:
                    print(f"      {vty.line_range}: transport_input={vty.transport_input}")
            elif f.rule_id == "MGMT-002":
                print(f"    HTTP enabled: {fixed_config.management.http_enabled}")
            elif f.rule_id == "MGMT-003":
                for vty in fixed_config.management.vty_lines:
                    print(f"      VTY {vty.line_range}: access_class={vty.access_class}")
            elif f.rule_id == "MGMT-004":
                for comm in fixed_config.snmp.communities:
                    print(f"      SNMP community: {comm.name} ({comm.permission})")
            elif f.rule_id == "MGMT-005":
                print(f"    enable_password_type: {fixed_config.authentication.enable_password_type}")
                print(f"    password_encryption: {fixed_config.services.password_encryption}")
                for u in fixed_config.authentication.local_users:
                    print(f"      User {u.username}: password_type={u.password_type}")
            elif f.rule_id == "MGMT-006":
                for vty in fixed_config.management.vty_lines:
                    print(f"      VTY {vty.line_range}: has_timeout={vty.has_timeout}")
                if fixed_config.management.console:
                    print(f"      Console: has_timeout={fixed_config.management.console.has_timeout}")
            elif f.rule_id == "MGMT-007":
                print(f"    ssh_version: {fixed_config.management.ssh_version}")
            elif f.rule_id == "MGMT-008":
                print(f"    aaa_enabled: {fixed_config.authentication.aaa_enabled}")
            elif f.rule_id == "MGMT-009":
                print(f"    login_banner: {bool(fixed_config.banners.login_banner)}")
                print(f"    motd_banner: {bool(fixed_config.banners.motd_banner)}")
            elif f.rule_id == "BOUNDARY-001":
                for acl in fixed_config.access_lists:
                    for entry in acl.entries:
                        print(f"      ACL {acl.name}: {entry.action} {entry.source} {entry.destination}")
            elif f.rule_id == "BOUNDARY-002":
                print(f"    ip_source_route: {fixed_config.services.ip_source_route}")
            elif f.rule_id == "BOUNDARY-003":
                print(f"    cdp_globally: {fixed_config.services.cdp_globally_enabled}")
                for iface in fixed_config.interfaces:
                    if iface.is_wan:
                        print(f"      {iface.name}: cdp={iface.cdp_enabled}, is_wan={iface.is_wan}")
            elif f.rule_id == "LOG-001":
                print(f"    remote_hosts: {fixed_config.logging.remote_hosts}")
            elif f.rule_id == "LOG-002":
                print(f"    ntp_servers: {fixed_config.ntp.servers}")
                print(f"    ntp_auth: {fixed_config.ntp.authentication_enabled}")
            elif f.rule_id == "CRYPTO-001":
                for p in fixed_config.vpn.ipsec_proposals:
                    print(f"      Proposal {p.name}: enc={p.encryption}, hash={p.hash_algorithm}, dh={p.dh_group}")
        
        # Show relevant section of fixed raw config
        print(f"\n  FIXED RAW CONFIG (first 80 lines):")
        for i, line in enumerate(fixed_raw.splitlines()[:80], 1):
            print(f"    {i:3d}: {line}")
        if len(fixed_raw.splitlines()) > 80:
            print(f"    ... ({len(fixed_raw.splitlines()) - 80} more lines)")
        
        FAIL_FILES.append((fname, [(f.rule_id, f.title, f.severity.value) for f in fixed_findings]))
    else:
        print(f"  -> ALL FINDINGS RESOLVED. PASS")
        PASS_FILES.append(fname)

print(f"\n\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")
print(f"\nPASSED ({len(PASS_FILES)}):")
for f in PASS_FILES:
    print(f"  [PASS] {f}")

print(f"\nFAILED ({len(FAIL_FILES)}):")
for f, details in FAIL_FILES:
    print(f"  [FAIL] {f}")
    if isinstance(details, str):
        print(f"         {details}")
    else:
        for rule_id, title, severity in details:
            print(f"         [{severity}] {rule_id}: {title}")
