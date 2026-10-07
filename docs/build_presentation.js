// Build: npm install pptxgenjs && node docs/build_presentation.js docs/presentation.pptx
// The .pptx is git-ignored (*.pptx: submission artefacts go to the portal); this script is the source.
// NetAuditAI: five-slide technical presentation (updates.md 3.2). Every number is from benchmark/RESULTS.md or a test.
const pptxgen = require("pptxgenjs");
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9"; // 10 x 5.625 in
pres.title = "NetAuditAI";

const INK = "0F1B2D", INK2 = "1B2A41", WHITE = "FFFFFF", TEXT = "1F2933", MUTED = "5B6776",
      AMBER = "F2A900", TEAL = "0E8A7E", RED = "C8423B", TINT = "EEF2F6";
const H = "Cambria", B = "Calibri";
const txt = (s, t, o) => s.addText(t, { isTextBox: true, fontFace: B, color: TEXT, margin: 0, ...o });
const badge = (s, n, x, y, fill = AMBER, color = INK) => {
  s.addShape(pres.shapes.OVAL, { x, y, w: 0.42, h: 0.42, fill: { color: fill }, line: { color: fill } });
  txt(s, String(n), { x, y, w: 0.42, h: 0.42, fontSize: 14, bold: true, color, align: "center", valign: "middle" });
};

// ── 1. Problem and answer ─────────────────────────────────────────────────────
let s = pres.addSlide();
s.background = { color: INK };
txt(s, "SIH 26155 · NTRO · Cybersecurity", { x: 0.6, y: 0.45, w: 8.8, h: 0.3, fontSize: 12, color: AMBER, bold: true });
txt(s, "NetAuditAI", { x: 0.6, y: 0.85, w: 8.8, h: 0.8, fontFace: H, fontSize: 44, bold: true, color: WHITE });
txt(s, "Audits any vendor's configuration against NIST, DISA STIG, ISO 27001 and CIS, and proves every verdict with the line that decides it.",
  { x: 0.6, y: 1.7, w: 8.6, h: 0.75, fontSize: 18, color: "CADCFC" });
const stats = [["89/112", "insecure settings caught as decided FAILs on labelled fixtures"],
               ["21/21", "on never-seen real configurations (held-out; first run 20/21)"],
               ["0", "false alarms, and 0 insecure settings called fine"]];
stats.forEach(([n, l], i) => {
  const x = 0.6 + i * 3.0;
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 2.85, w: 2.75, h: 1.75, rectRadius: 0.08, fill: { color: INK2 }, line: { color: INK2 } });
  txt(s, n, { x: x + 0.2, y: 3.0, w: 2.35, h: 0.75, fontFace: H, fontSize: 40, bold: true, color: AMBER });
  txt(s, l, { x: x + 0.2, y: 3.8, w: 2.35, h: 0.7, fontSize: 12, color: "D6DEE8" });
});
txt(s, "Problem: every vendor writes security differently, and a tool that guesses is worse than none.",
  { x: 0.6, y: 4.85, w: 8.8, h: 0.35, fontSize: 12, italic: true, color: "9FB0C4" });
s.addNotes("Problem and answer in one line. Numbers: benchmark/RESULTS.md (planted 18/20 also holds).");

// ── 2. Architecture ───────────────────────────────────────────────────────────
s = pres.addSlide();
s.background = { color: WHITE };
txt(s, "One pipeline, any syntax", { x: 0.5, y: 0.35, w: 9, h: 0.6, fontFace: H, fontSize: 32, bold: true, color: INK });
txt(s, "Same diagram as the two-page architecture brief (docs/architecture-brief.pdf)", { x: 0.5, y: 0.95, w: 9, h: 0.3, fontSize: 12, color: MUTED });
const stages = [["Upload / collect", "UTF-8, 2 MB, secrets redacted before any AI"],
                ["Detect vendor", "Deterministic; an AI guess is evidence only"],
                ["Read", "Cisco IOS, FortiGate parsers · generic tokenizer · JSON / Terraform flattening"],
                ["Normalize", "Vendor-neutral facts: mgmt.ssh.version, snmp.community …"],
                ["Decide", "27 checks → 82 requirements (NIST, STIG, ISO, CIS)"],
                ["Report", "Attack paths, fixes verified on a copy, PDF, hash-chained ledger"]];
stages.forEach(([t, d], i) => {
  const col = i % 3, row = Math.floor(i / 3);
  const x = 0.5 + col * 3.05, y = 1.5 + row * 1.85;
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 2.8, h: 1.55, rectRadius: 0.08, fill: { color: TINT }, line: { color: TINT } });
  badge(s, i + 1, x + 0.18, y + 0.18);
  txt(s, t, { x: x + 0.72, y: y + 0.18, w: 1.95, h: 0.42, fontSize: 15, bold: true, color: INK, valign: "middle" });
  txt(s, d, { x: x + 0.18, y: y + 0.72, w: 2.5, h: 0.75, fontSize: 11.5, color: TEXT });
  if (col < 2) s.addShape(pres.shapes.CHEVRON, { x: x + 2.86, y: y + 0.64, w: 0.16, h: 0.26, fill: { color: AMBER }, line: { color: AMBER } });
});
s.addNotes("Unknown vendors go through the generic tokenizer and shipped or taught recognizers; nothing vendor-specific is guessed.");

// ── 3. Vendor-agnostic proof ──────────────────────────────────────────────────
s = pres.addSlide();
s.background = { color: WHITE };
txt(s, "Vendor-agnostic, and measured", { x: 0.5, y: 0.35, w: 9, h: 0.6, fontFace: H, fontSize: 32, bold: true, color: INK });
const how = [["Parser", "Cisco IOS / IOS-XE, FortiGate: confirmed by grammar coverage"],
             ["Seed knowledge", "243 reviewed recognizers, 13 dialects: Junos, PAN-OS, Arista, Huawei, SONiC, Cumulus …"],
             ["Flattening", "AWS / Azure / GCP firewall exports and Terraform, cited at the rule's own line"],
             ["Teach", "An admin confirms one line; the recognizer is reused, no AI"]];
how.forEach(([t, d], i) => {
  const y = 1.2 + i * 0.95;
  badge(s, i + 1, 0.5, y, TEAL, WHITE);
  txt(s, t, { x: 1.05, y: y - 0.02, w: 3.4, h: 0.32, fontSize: 15, bold: true, color: INK });
  txt(s, d, { x: 1.05, y: y + 0.3, w: 3.5, h: 0.55, fontSize: 11.5, color: TEXT });
});
s.addChart(pres.charts.BAR, [{ name: "Detected as decided FAIL (%)", labels: ["Planted (18/20)", "Fixtures (89/112)", "Held-out (21/21)"],
  values: [90, 79, 100] }], {
  x: 4.9, y: 1.15, w: 4.6, h: 3.1, barDir: "bar", chartColors: [AMBER],
  showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0\"%\"", dataLabelColor: INK, dataLabelFontSize: 11,
  catAxisLabelColor: TEXT, catAxisLabelFontSize: 11, valAxisHidden: true, valAxisMaxVal: 110, valAxisMinVal: 0,
  valGridLine: { style: "none" }, catGridLine: { style: "none" }, showLegend: false,
  showTitle: true, title: "Insecure settings caught (no AI)", titleFontSize: 13, titleColor: INK,
});
txt(s, "0 missed · 0 false alarms in every set · undecided is an answer, never a guess", { x: 4.9, y: 4.35, w: 4.6, h: 0.3, fontSize: 11.5, bold: true, color: TEAL });
txt(s, "Held-out: 9 real configurations (pybatfish), labels committed before the first run; the one first-run miss was a parser bug, now fixed.",
  { x: 0.5, y: 4.95, w: 9, h: 0.45, fontSize: 10.5, color: MUTED });
s.addNotes("Source: benchmark/RESULTS.md, generated by backend/scripts/benchmark.py. Fixtures 23 undecided are listed there.");

// ── 4. Trust ──────────────────────────────────────────────────────────────────
s = pres.addSlide();
s.background = { color: WHITE };
txt(s, "Why a verdict can be trusted", { x: 0.5, y: 0.35, w: 9, h: 0.6, fontFace: H, fontSize: 32, bold: true, color: INK });
const trust = [["AI proposes, a human confirms", "AI answers only undecided checks; a proposal never changes posture until an admin confirms it."],
               ["0 of 6 prompt injections", "Config text is fenced as data; a fully hijacked model is tested to change nothing."],
               ["Every citation checked", "An independent test re-reads every cited line, attack-path step and posture over all benchmark files."],
               ["Every attack path proved", "Each chain appears on its positive config and disappears when only its one fix is applied."],
               ["Tamper-evident ledger", "Scans and reports are hash-chained; a report PDF is verified byte for byte."],
               ["Secrets never leave", "Passwords, communities and keys are redacted in every response, PDF, cache and export."]];
trust.forEach(([t, d], i) => {
  const col = i % 2, row = Math.floor(i / 2);
  const x = 0.5 + col * 4.6, y = 1.2 + row * 1.35;
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 4.35, h: 1.15, rectRadius: 0.08, fill: { color: TINT }, line: { color: TINT } });
  s.addShape(pres.shapes.OVAL, { x: x + 0.2, y: y + 0.22, w: 0.3, h: 0.3, fill: { color: TEAL }, line: { color: TEAL } });
  txt(s, t, { x: x + 0.65, y: y + 0.15, w: 3.55, h: 0.4, fontSize: 14, bold: true, color: INK, valign: "middle" });
  txt(s, d, { x: x + 0.65, y: y + 0.55, w: 3.55, h: 0.55, fontSize: 11, color: TEXT });
});
s.addNotes("Tests: test_citations.py, test_path_proof.py, injection probe, ledger tests, redaction leak tests.");

// ── 5. What the judge saw, and what is not done ───────────────────────────────
s = pres.addSlide();
s.background = { color: INK };
txt(s, "What you saw, and what is honestly not done", { x: 0.5, y: 0.35, w: 9, h: 0.6, fontFace: H, fontSize: 28, bold: true, color: WHITE });
txt(s, "The two-minute demo", { x: 0.5, y: 1.15, w: 4.3, h: 0.35, fontSize: 16, bold: true, color: AMBER });
const saw = ["Cisco, PAN-OS, brace-style Junos and Terraform in one scan",
             "CVE context for the stated IOS-XE release, offline",
             "A remote-takeover path, its one fix, and its proof",
             "A report PDF verified against the ledger; one changed byte fails"];
txt(s, saw.map((t, i) => ({ text: t, options: { bullet: true, breakLine: i < saw.length - 1 } })),
  { x: 0.5, y: 1.6, w: 4.3, h: 2.8, fontSize: 13, color: "E3E9F0", paraSpaceAfter: 8, valign: "top" });
txt(s, "Not done", { x: 5.2, y: 1.15, w: 4.3, h: 0.35, fontSize: 16, bold: true, color: "F28B82" });
const not = ["Azure / GCP rules: an open rule fails; a restricted one stays undecided",
             "CVE context for PAN-OS (the platform is never confirmed)",
             "Held-out set covers 3 vendor families, not 4",
             "SONiC AAA order and SSH policy; Cumulus startup.yaml",
             "Every result is from the configuration, not a live test of the device"];
txt(s, not.map((t, i) => ({ text: t, options: { bullet: true, breakLine: i < not.length - 1 } })),
  { x: 5.2, y: 1.6, w: 4.3, h: 2.8, fontSize: 13, color: "E3E9F0", paraSpaceAfter: 8, valign: "top" });
txt(s, "Branch final-updates · every number reproducible with backend/scripts/benchmark.py",
  { x: 0.5, y: 4.95, w: 9, h: 0.3, fontSize: 11, color: "9FB0C4" });
s.addNotes("Close on the limits: judges trust a tool that says what it cannot do.");

pres.writeFile({ fileName: process.argv[2] }).then((f) => console.log("wrote " + f));
