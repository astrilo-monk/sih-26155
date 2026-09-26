"""
The per-device compliance report.

    scan response (already redacted)  +  remediation plan  →  document model  →  PDF bytes

The document is built in two steps on purpose. ``report_blocks`` produces a plain structure -
headings, paragraphs, tables, monospace blocks -which is what the tests read, so what the PDF
says can be asserted without parsing PDF streams. ``render_pdf`` only lays that structure out.

Nothing is evaluated, scored or remediated here: the report states what the scan already decided.
Its two rules are the product's own:

* it never reports something the configuration does not state -a serial number or model is printed only
  when the uploaded text states it (``show version`` / ``show inventory`` output), never inferred;
* it never prints a secret. Every string it receives has already been redacted by the API layer
  (``config_redactor`` / ``display_scrub``), and ``tests/test_pdf_report.py`` re-checks the
  rendered document against the secrets of the configuration it was built from.
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Optional

# A block is (kind, payload): "h1"/"h2"/"p"/"note" carry text, "table" carries (headers, rows),
# "mono" carries a list of configuration lines, "spacer" carries nothing.
Block = tuple

STATUS_WORDS = {
    "pass": "PASS",
    "fail": "FAIL",
    "unknown": "UNKNOWN",
    "not_configured": "NOT CONFIGURED",
    "n_a": "N/A",
    "partial": "PARTIAL",
}
ASSURANCE_WORDS = {
    "parser": "dedicated parser",
    "confirmed": "confirmed recognizer",
    "default": "documented default",
    "heuristic": "heuristic reading (provisional)",
    "ai_verified": "AI proposal (provisional)",
}
REMEDIATION_WORDS = {
    "fixed": "Deterministic fix generated and verified by rescan",
    "needs_input": "A value is needed before the fix can be generated",
    "manual_review": "Change this by hand -no safe automatic recipe",
    "verification_failed": "Generated, but the rescan did not confirm it -not applied",
    "no_recipe": "No deterministic recipe for this control",
    "vendor_unverified": "Vendor not confirmed -no vendor commands are generated",
    "provisional": "The finding is provisional -remediation waits for confirmation",
    "not_failing": "Not failing",
}
# The catalog's framework keys, spelled the way the framework is named
FRAMEWORK_NAMES = {"NIST_800_53": "NIST SP 800-53", "CIS": "CIS Benchmarks",
                   "DISA_STIG": "DISA STIG", "ISO_27001": "ISO/IEC 27001"}
# Frameworks this build maps. Anything else is named as not mapped rather than left to be assumed.
MAPPED_FRAMEWORKS = ("NIST SP 800-53", "CIS Benchmarks", "DISA STIG", "ISO/IEC 27001")
UNMAPPED_FRAMEWORKS = ("PCI DSS", "CIS Controls v8")


def _device(scan, index: int) -> dict:
    devices = getattr(scan, "devices", None) or []
    return devices[index] if index < len(devices) else {}


def _identification(scan, index: int):
    return next((v for v in (getattr(scan, "vendor_identification", None) or [])
                 if v.config_index == index), None)


def _vendor_line(scan, index: int) -> str:
    identification = _identification(scan, index)
    if identification is None:
        return "not identified"
    status = {"confirmed": "confirmed", "unverified": "unverified", "unknown": "not identified"}.get(
        identification.status, identification.status)
    if identification.status == "confirmed":
        return f"{identification.detected_vendor} ({status}, dedicated parser)"
    if identification.status == "unverified":
        return f"resembles {identification.detected_vendor} ({status}) -generic analysis"
    return f"{status} -generic analysis"


def _results_for(scan, index: int) -> list:
    return [r for r in (getattr(scan, "results", None) or []) if r.config_index == index]


def identification_block(scan, index: int) -> list[Block]:
    """Device identification: what the uploaded configuration actually states about the device."""
    device = _device(scan, index)
    identification = _identification(scan, index)
    rows = [
        ["Hostname", device.get("hostname") or "not stated in the configuration"],
        ["Vendor / platform", _vendor_line(scan, index)],
        ["OS / firmware version", device.get("os_version") if device.get("os_version") not in (None, "", "unknown")
         else "not stated in the configuration"],
        ["Hardware model", device.get("model") or "not stated in the configuration"],
        ["Serial number", device.get("serial") or "not stated in the uploaded file"],
    ]
    if identification is not None and identification.parse_coverage is not None:
        rows.append(["Parse coverage", f"{round(identification.parse_coverage * 100)}% of lines read by the parser "
                                       f"({identification.uncovered_lines} outside its grammar)"])
    blocks: list[Block] = [("h2", "1. Device identification"), ("table", (["Item", "Value"], rows))]
    if not device.get("serial"):
        blocks.append(("note", "A configuration file rarely carries the serial number: upload it together with "
                               "'show version' or 'show inventory' output to have it reported. NetAuditAI states only "
                               "what the uploaded file states."))
    return blocks


_ORDER = ["critical", "high", "medium", "low"]


def glance_block(scan, index: int, plan=None) -> list[Block]:
    """One screen for a reader who will not read the rest: risk, score, the worst problems, what is left."""
    decisive = {"parser", "confirmed", "default"}
    failed: dict[str, object] = {}
    for r in _results_for(scan, index):
        if r.status == "fail" and r.assurance in decisive:
            kept = failed.get(r.control_id)
            if kept is None or _ORDER.index(r.severity) < _ORDER.index(kept.severity):
                failed[r.control_id] = r
    blocks: list[Block] = [("h2", "At a glance")]
    if not failed:
        blocks.append(("p", "No problem was found from decisive evidence."
                            + (f" Score {scan.posture}/100." if scan.posture is not None else "")))
        return blocks
    worst = min((r.severity for r in failed.values()), key=_ORDER.index)
    counts = {s: sum(1 for r in failed.values() if r.severity == s) for s in _ORDER}
    risk = (_device(scan, index) or {}).get("risk")
    level = f"{risk['level'].upper()} ({risk['score']}/100)" if risk else worst.upper()
    blocks.append(("p", f"Risk: {level}. {len(failed)} problem{'s' if len(failed) != 1 else ''} found ("
                        + ", ".join(f"{n} {s}" for s, n in counts.items() if n) + ")."))
    if risk:
        blocks.append(("p", f"Why: {'; '.join(risk['reasons'])}. Risk = {risk['formula']}."))
    if scan.posture is not None:
        line = f"Score: {scan.posture}/100, from the {scan.coverage}% of checks that could be decided."
        after = getattr(plan, "after", None) if plan is not None else None
        fixed = list(getattr(plan, "fixed_controls", []) or []) if plan is not None else []
        if after is not None and fixed and after.posture is not None:
            line += (f" With the {len(fixed)} verified automatic fix{'es' if len(fixed) != 1 else ''} applied: "
                     f"{after.posture}/100.")
        blocks.append(("p", line))
    impact = {f.rule_id: f.security_impact for f in (scan.findings or []) if (f.config_index or 0) == index}
    top = sorted(failed.values(), key=lambda r: (_ORDER.index(r.severity), r.control_id))[:3]
    blocks.append(("table", (["Most serious problems", "Why it matters"],
                             [[f"{r.title} ({r.severity})", impact.get(r.control_id) or "-"] for r in top])))
    if plan is not None:
        human = [r for r in plan.remediations
                 if r.status in ("manual_review", "needs_input", "vendor_unverified", "no_recipe", "verification_failed")]
        if human:
            blocks.append(("p", f"Needs a person: {len(human)} problem{'s' if len(human) != 1 else ''} cannot be "
                                "fixed automatically. Section 5 says what to change for each."))
    return blocks


def summary_block(scan, index: int) -> list[Block]:
    results = _results_for(scan, index)
    by_control: dict[str, list] = {}
    for r in results:
        by_control.setdefault(r.control_id, []).append(r)
    decisive = {"parser", "confirmed", "default"}
    failed = sorted({r.control_id for r in results if r.status == "fail" and r.assurance in decisive})
    passed = sorted({c for c, g in by_control.items()
                     if any(r.status == "pass" and r.assurance in decisive for r in g)
                     and not any(r.status == "fail" for r in g)})
    severities = {s: 0 for s in ("critical", "high", "medium", "low")}
    for control_id in failed:
        worst = min((r.severity for r in by_control[control_id]),
                    key=lambda s: ["critical", "high", "medium", "low"].index(s) if s in severities else 9)
        severities[worst] = severities.get(worst, 0) + 1

    rows = [
        ["Security posture", f"{scan.posture}/100" if scan.posture is not None else
         "not assessed -no control could be decided from validated evidence"],
        ["Coverage", f"{scan.coverage}% of applicable controls decided from evidence"],
        ["Checks assessed", f"{len(passed) + len(failed)} decided ({len(passed)} passed, {len(failed)} failed)"],
        ["Checks needing input", str(sum(1 for c in by_control if c not in passed and c not in failed))],
        ["Problems by severity", ", ".join(f"{n} {name}" for name, n in severities.items() if n) or "none"],
    ]
    blocks: list[Block] = [("h2", "2. Assessment summary"), ("table", (["Item", "Value"], rows))]
    if scan.posture is not None and scan.coverage < 100 and scan.posture_bounds:
        blocks.append(("p", f"The posture covers only the {scan.coverage}% that could be decided. If every undecided "
                            f"check failed, it would be {scan.posture_bounds[0]}; if every one passed, "
                            f"{scan.posture_bounds[1]}."))
    if scan.critical_unassessed:
        blocks.append(("note", "Critical controls that could not be assessed: "
                               f"{', '.join(scan.critical_unassessed)}. Do not treat the device as compliant on "
                               "these points."))
    return blocks


def findings_block(scan, index: int) -> list[Block]:
    """Every control, with its result, how it was established and the lines it cites."""
    rows = []
    for r in sorted(_results_for(scan, index), key=lambda r: r.control_id):
        status = STATUS_WORDS.get(r.status, r.status.upper())
        if r.proposed_status:
            status = f"{status} (AI proposes {r.proposed_status.upper()}, awaiting confirmation)"
        evidence = ", ".join(str(n) for n in r.evidence.line_numbers) or "-"
        rows.append([
            r.control_id,
            f"{r.title}{f' -{r.scope}' if r.scope else ''}",
            r.severity,
            status,
            ASSURANCE_WORDS.get(r.assurance, "not established") if r.assurance else "not established",
            evidence,
        ])
    return [
        ("h2", "3. Compliance findings"),
        ("table", (["Control", "Requirement", "Severity", "Result", "Established by", "Lines"], rows)),
        ("note", "PASS and FAIL are reported only from decisive evidence: a dedicated parser, a human-confirmed "
                 "recognizer or a documented platform default. Heuristic and AI readings are shown as provisional "
                 "and are never counted as passed or failed."),
    ]


def frameworks_block(scan, index: int) -> list[Block]:
    blocks: list[Block] = [("h2", "4. Framework view")]
    views = getattr(scan, "frameworks", None) or []
    for view in views:
        rows = []
        for requirement in view.requirements:
            controls = [c for c in requirement.controls if c.config_index == index]
            if not controls:
                continue
            status = STATUS_WORDS.get(requirement.status, requirement.status.upper())
            rows.append([
                requirement.requirement_id,
                requirement.title,
                f"{status} (provisional)" if requirement.provisional else status,
                ", ".join(c.control_id for c in controls),
            ])
        if rows:
            blocks.append(("p", f"{FRAMEWORK_NAMES.get(view.framework, view.framework)} -{view.version}"))
            blocks.append(("table", (["Requirement", "Title", "Result", "Controls"], rows)))
    if len(blocks) == 1:
        blocks.append(("p", "No framework requirement could be reported for this device."))
    if getattr(scan, "framework", None):
        blocks.append(("p", f"Assessed against {FRAMEWORK_NAMES.get(scan.framework, scan.framework)} only, as "
                            "selected when the scan was started."))
    blocks.append(("note", f"Mapped in this build: {', '.join(MAPPED_FRAMEWORKS)}. Not mapped and not claimed: "
                           f"{', '.join(UNMAPPED_FRAMEWORKS)}. A framework view regroups configuration controls; "
                           "it is not a certification and does not cover requirements outside device configuration."))
    return blocks


def _diff_commands(diff: str) -> list[str]:
    """The added / removed configuration lines of a unified diff, as a command sequence."""
    lines = []
    for line in (diff or "").split("\n"):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            lines.append(f"  {line[1:].strip()}")
        elif line.startswith("-"):
            lines.append(f"  no {line[1:].strip()}" if not line[1:].strip().startswith("no ") else f"  {line[1:].strip()}")
    return lines


def remediation_block(plan, index: int) -> list[Block]:
    """Remediation paths: the deterministic change per failing control, or why there is none."""
    blocks: list[Block] = [("h2", "5. Remediation")]
    if plan is None:
        blocks.append(("p", "No remediation plan was generated for this device."))
        return blocks

    items = [r for r in plan.remediations if r.status != "not_failing"]
    if not items:
        blocks.append(("p", "Nothing to remediate: no decisive failure was found for this device."))
        return blocks

    if plan.vendor_status != "confirmed":
        blocks.append(("note", f"The vendor of {plan.device_hostname} is not confirmed, so NetAuditAI generates no "
                               "vendor commands for it. Each problem is stated with what to change; you "
                               "can propose a command in the application, where it is checked against this "
                               "configuration before anything is accepted."))
    for item in items:
        blocks.append(("h3", f"{item.rule_id} -{item.title}"))
        rows = [["Status", REMEDIATION_WORDS.get(item.status, item.status)]]
        if item.scopes:
            rows.append(["Scope", ", ".join(item.scopes)])
        if item.evidence.line_numbers:
            rows.append(["Before (cited lines)", ", ".join(str(n) for n in item.evidence.line_numbers)])
        if item.control_status_before or item.control_status_after:
            rows.append(["Control state", f"{(item.control_status_before or '-').upper()} → "
                                          f"{(item.control_status_after or '-').upper()}"])
        if item.missing_inputs:
            rows.append(["Needed from you", ", ".join(item.missing_inputs)])
        blocks.append(("table", (["Item", "Value"], rows)))
        if item.explanation or item.reason:
            blocks.append(("p", item.explanation or item.reason))
        commands = _diff_commands(item.diff)
        if commands:
            blocks.append(("p", "Configuration change (verified against a copy of the uploaded file, never executed "
                                "on a device):"))
            blocks.append(("mono", commands))
        for check in item.checks:
            blocks.append(("p", f"{'PASSED' if check.passed else 'FAILED'} -{check.name}: {check.detail}"))
    return blocks


def unresolved_block(scan, index: int) -> list[Block]:
    """What the scan could not decide, and what it needs -the queue an administrator works through."""
    undecided = [r for r in _results_for(scan, index) if r.status in ("unknown", "not_configured")]
    blocks: list[Block] = [("h2", "6. Checks that need your input")]
    if not undecided:
        blocks.append(("p", "None: every applicable control was decided from evidence."))
        return blocks
    rows = [[r.control_id, r.title, STATUS_WORDS.get(r.status, r.status.upper()), r.reason] for r in undecided]
    blocks.append(("table", (["Control", "Requirement", "Result", "Why it could not be decided"], rows)))
    blocks.append(("note", "These are not failures and not passes. In the application's Teach page you "
                           "can point NetAuditAI at the configuration line that answers one and state what it means; "
                           "the same configuration is then re-checked and the result becomes decisive."))
    return blocks


def attack_paths_block(scan, index: int) -> list[Block]:
    """How this device's confirmed problems chain together, step by step, and the fix that breaks each chain."""
    paths = [p for p in (getattr(scan, "attack_paths", None) or []) if p.get("config_index") == index]
    if not paths:
        return []
    blocks: list[Block] = [("h2", "Potential attack paths"),
                           ("p", "Each path chains problems this report confirms; every step is a decided FAIL. It shows "
                                 "what the configuration allows, not a test of the live device.")]
    for path in paths:
        blocks.append(("h3", f"{path['title']} ({path['severity'].upper()})"))
        rows = [[str(i), step["title"], ", ".join(c["control_id"] for c in step["controls"]),
                 "; ".join(f"line {line['number']}: {line['text']}" for c in step["controls"] for line in c["lines"][:1])
                 or "not configured"]
                for i, step in enumerate(path["steps"], 1)]
        rows.append(["", f"Result: {path['outcome']}", "", ""])
        blocks.append(("table", (["#", "Step", "Checks", "Evidence"], rows)))
        blocks.append(("p", f"Break it: fix {' and '.join(path['break_with'])} (the \"{path['break_step']}\" step) "
                            "and the whole path closes."))
    return blocks


def report_blocks(scan, index: int, plan=None, generated_at: Optional[datetime] = None) -> list[Block]:
    """The whole report for one device, as a document model."""
    device = _device(scan, index)
    when = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    blocks: list[Block] = [
        ("h1", f"Network security compliance report -{device.get('hostname') or 'unnamed device'}"),
        ("p", f"NetAuditAI · generated {when} · scan {scan.scan_id}"),
    ]
    if index in (getattr(scan, "unreadable_configs", None) or []):
        blocks.append(("note", "This file does not contain enough recognizable configuration to assess. "
                               "No posture was calculated for it."))
    for section in (glance_block(scan, index, plan), attack_paths_block(scan, index), identification_block(scan, index),
                    summary_block(scan, index),
                    findings_block(scan, index),
                    frameworks_block(scan, index), remediation_block(plan, index), unresolved_block(scan, index)):
        blocks.extend(section)
    blocks.append(("note", "Secrets (passwords, keys, SNMP community strings) are redacted by the backend before "
                           "anything leaves it, including this report. Evidence keeps its line numbers so every "
                           "result can be checked against the original file."))
    return blocks


def report_text(blocks: list[Block]) -> str:
    """The report as plain text -what the PDF says, for tests and for a quick check."""
    out = []
    for kind, payload in blocks:
        if kind in ("h1", "h2", "h3", "p", "note"):
            out.append(str(payload))
        elif kind == "table":
            headers, rows = payload
            out.append(" | ".join(headers))
            out.extend(" | ".join(str(c) for c in row) for row in rows)
        elif kind == "mono":
            out.extend(payload)
    return "\n".join(out)


def render_pdf(blocks: list[Block], title: str = "Compliance report") -> bytes:
    """Lay the document model out as a PDF."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ink, muted, rule = colors.HexColor("#101418"), colors.HexColor("#5b6670"), colors.HexColor("#d5dade")
    base = getSampleStyleSheet()["BodyText"]
    styles = {
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=16, leading=20,
                             spaceAfter=2, textColor=ink),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12, leading=15,
                             spaceBefore=14, spaceAfter=4, textColor=ink),
        "h3": ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=10, leading=13,
                             spaceBefore=8, spaceAfter=2, textColor=ink),
        "p": ParagraphStyle("p", parent=base, fontName="Helvetica", fontSize=9, leading=12,
                            alignment=TA_LEFT, textColor=ink, spaceAfter=3),
        "note": ParagraphStyle("note", parent=base, fontName="Helvetica-Oblique", fontSize=8, leading=11,
                               textColor=muted, spaceBefore=3, spaceAfter=3),
        "cell": ParagraphStyle("cell", parent=base, fontName="Helvetica", fontSize=8, leading=10, textColor=ink),
        "cellhead": ParagraphStyle("cellhead", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10,
                                   textColor=ink),
        "mono": ParagraphStyle("mono", parent=base, fontName="Courier", fontSize=8, leading=10, textColor=ink),
    }

    def escape(text) -> str:
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    story = []
    for kind, payload in blocks:
        if kind in ("h1", "h2", "h3", "p", "note"):
            story.append(Paragraph(escape(payload), styles[kind]))
        elif kind == "mono":
            story.append(Spacer(1, 2))
            for line in payload:
                story.append(Paragraph(escape(line).replace(" ", "&nbsp;"), styles["mono"]))
            story.append(Spacer(1, 4))
        elif kind == "table":
            headers, rows = payload
            if not rows:
                continue
            data = [[Paragraph(escape(h), styles["cellhead"]) for h in headers]]
            data += [[Paragraph(escape(c), styles["cell"]) for c in row] for row in rows]
            table = Table(data, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, rule),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(KeepTogether(table) if len(rows) <= 6 else table)
            story.append(Spacer(1, 4))

    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, title=title, author="NetAuditAI",
                      leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm).build(story)
    return buffer.getvalue()


def executive_blocks(scan, index: int, plan=None, generated_at: Optional[datetime] = None) -> list[Block]:
    """One page for a decision-maker: risk, score, attack paths and the first three things to do."""
    device = _device(scan, index)
    when = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    blocks: list[Block] = [
        ("h1", f"Executive summary -{device.get('hostname') or 'unnamed device'}"),
        ("p", f"NetAuditAI · generated {when} · scan {scan.scan_id} · the full technical report has every finding, "
              "its evidence and its fix"),
        *glance_block(scan, index, plan),
    ]
    paths = [p for p in (getattr(scan, "attack_paths", None) or []) if p.get("config_index") == index]
    if paths:
        blocks.append(("h2", "How an attacker could chain these problems"))
        blocks.append(("table", (["Potential attack path", "Outcome", "Breaks when you fix"],
                                 [[f"{p['title']} ({p['severity']})", p["outcome"], " and ".join(p["break_with"])]
                                  for p in paths])))
    todo = []
    if plan is not None:
        # the fix that breaks the most severe attack path first, then a fix that is ready, then by check
        breaking: dict[str, int] = {}
        for p in paths:
            for c in p["break_with"]:
                breaking[c] = min(breaking.get(c, len(_ORDER)), _ORDER.index(p["severity"]))
        items = [r for r in plan.remediations if r.status != "not_failing"]
        items.sort(key=lambda r: (breaking.get(r.rule_id, len(_ORDER)), r.status != "fixed", r.rule_id))
        todo = [[r.rule_id, r.title, REMEDIATION_WORDS.get(r.status, r.status)
                 + ("; breaks an attack path" if r.rule_id in breaking else "")] for r in items[:3]]
    if todo:
        blocks.append(("h2", "What to do first"))
        blocks.append(("table", (["Check", "Problem", "How"], todo)))
    return blocks


def device_report_pdf(scan, index: int, plan=None, generated_at: Optional[datetime] = None,
                      ledger_entry: Optional[dict] = None, executive: bool = False) -> bytes:
    device = _device(scan, index)
    blocks = (executive_blocks if executive else report_blocks)(scan, index, plan, generated_at)
    if ledger_entry:
        blocks.append(("note", f"Audit ledger: the scan behind this report is entry #{ledger_entry['seq']} "
                               f"(hash {ledger_entry['hash'][:16]}…). This PDF's own SHA-256 is recorded when it is "
                               "generated: any copy can be checked with POST /api/ledger/verify-report."))
    return render_pdf(blocks, title=f"Compliance report -{device.get('hostname') or 'device'}")
