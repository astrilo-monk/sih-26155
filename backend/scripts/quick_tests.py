"""Quick test suite: one fast pass over every layer, in a few minutes instead of the full suite's half hour.

    cd backend && python scripts/quick_tests.py              # run it (parallel when pytest-xdist is installed)
    cd backend && python scripts/quick_tests.py --list       # what it runs, and why
    cd backend && python scripts/quick_tests.py --budget 240 # fail if it takes longer than this many seconds

It is a smoke test, not a replacement: before merging to main, run the full suite (``python -m pytest -q``), which
adds the per-dialect coverage measurement, the seed expansion pass and the benchmark. What is left out is listed in
docs/testing.md.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

# (test file, -k expression or None, why it is here). Measured at 1 to 70 seconds each, one process, 2 cores.
QUICK: list[tuple[str, str | None, str]] = [
    ("tests/test_phase0_snapshots.py", None, "Cisco / FortiGate findings identical to the frozen Phase 0 snapshot"),
    ("tests/test_phase1_redaction.py", None, "secrets never leave the backend (passwords, keys, communities)"),
    ("tests/test_phase2_controls.py", None, "the 27-check catalog: ids, judges, framework mappings, results"),
    ("tests/test_phase4_facts.py", None, "parser facts for the confirmed vendors"),
    ("tests/test_phase5_heuristics.py", None, "generic-path heuristics stay provisional"),
    ("tests/test_phase6_recognizers.py", None, "recognizer safety gates (teaching)"),
    ("tests/test_teach_safety.py", None, "teaching traps that once produced a false PASS"),
    ("tests/test_checks_pack_c.py", None, "AUTH / CRYPTO-002 checks"),
    ("tests/test_checks_pack_d.py", None, "BOUNDARY-004 interface services"),
    ("tests/test_added_checks_snmpv3_routing_tls_ports.py", None, "MGMT-012, BOUNDARY-005/006, CRYPTO-003 on IOS and FortiGate"),
    ("tests/test_generic_new_checks.py", None, "the same checks on the generic path, and N/A from absence"),
    ("tests/test_seed_coverage.py", "snmp or tls or documented_default or scope_chain or top_level",
     "the newest seeds read their line and nothing near it; documented defaults"),
    ("tests/test_remediation_e2e.py", None, "one-click fixes: verified by rescanning, never regress"),
    ("tests/test_demo_fix_to_100.py", None, "the demo files still fix to 100"),
    ("tests/test_resolution_queue.py", None, "score, coverage and the undecided queue agree"),
    ("tests/test_scan_archive.py", None, "stored scans keep no secrets"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="show what runs, and why")
    parser.add_argument("--budget", type=int, default=300, help="fail when slower than this (seconds, default 300)")
    args = parser.parse_args()

    if args.list:
        for path, keyword, why in QUICK:
            print(f"{path}{f'  -k {keyword!r}' if keyword else ''}\n    {why}")
        return 0

    parallel = ["-n", "auto"] if importlib.util.find_spec("xdist") else []
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *parallel]
    # one pytest run: a -k expression applies to the whole run, so each filtered file goes in as its own node list
    plain = [path for path, keyword, _ in QUICK if keyword is None]
    filtered = [(path, keyword) for path, keyword, _ in QUICK if keyword is not None]
    nodes = []
    for path, keyword in filtered:
        collected = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
                                    path, "-k", keyword], cwd=BACKEND, capture_output=True, text=True)
        nodes += [line for line in collected.stdout.splitlines() if "::" in line]

    started = time.monotonic()
    result = subprocess.run([*command, *plain, *nodes], cwd=BACKEND)
    elapsed = time.monotonic() - started
    print(f"\nquick suite: {len(plain)} files + {len(nodes)} selected tests in {elapsed:.0f} s "
          f"(budget {args.budget} s{', parallel' if parallel else ''})")
    if result.returncode == 0 and elapsed > args.budget:
        print("quick suite passed but went over its time budget: move the slowest file to the full suite")
        return 2
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
