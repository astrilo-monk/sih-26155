# NetAuditAI - Complete Study Guide

This document is designed to help you and your teammates understand the entire NetAuditAI project from a high level. It focuses on *what* the code does and *how* the pieces fit together, making it perfect for preparing for your SIH (Smart India Hackathon) pitch.

---

## 1. The Executive Summary (Your Pitch)

**What is it?**
NetAuditAI is an AI-driven, multi-vendor network security compliance auditor. 

**What problem does it solve?**
Network engineers typically have to read through thousands of lines of raw configuration text (from routers and firewalls) to find security vulnerabilities. This is slow, error-prone, and requires deep expertise for every vendor (Cisco, Fortinet, etc.).

**How does NetAuditAI solve it?**
1. **Upload:** You upload a raw configuration file.
2. **Detect & Parse:** The system automatically figures out if it's Cisco or Fortinet, and translates the messy vendor text into a clean, standardized format.
3. **Analyze:** It runs deterministic security rules (checking for weak passwords, disabled logging, insecure protocols) against this clean data.
4. **Report & AI Fix:** It gives the network a security score, maps issues to standard frameworks (CIS, NIST), and uses AI (Google Gemini) to explain the vulnerabilities and generate the exact CLI commands needed to fix them.

---

## 2. The Architecture & Flow of Data

Imagine a user uploading a `router.cfg` file. Here is exactly how that data flows through your system:

### Step 1: The API Entry Point (`backend/app/api/`)
* **What it does:** This is the bouncer at the door. The `scan_configs` endpoint receives the file from the React frontend. It checks if the file is too big or if it's completely empty. If the file is valid, it passes the text to the Detection system.

### Step 2: Vendor Detection (`backend/app/parsers/detector.py`)
* **What it does:** It reads the first few lines of the text. If it sees words like `config system global` or `edit`, it knows it's a Fortinet firewall. If it sees `version 15.2` or `service password-encryption`, it knows it's a Cisco router. It does not rely on the user selecting a dropdown.

### Step 3: The Parsers (`backend/app/parsers/`)
* **What it does:** Once we know the vendor, the specific parser (`cisco_ios.py` or `fortinet.py`) takes over. These scripts read the raw text and extract important data (hostnames, user accounts, passwords, SNMP settings, interface IPs).
* **The Goal:** It takes vendor-specific gibberish and converts it into a `NormalizedConfig` Python object. This means the rest of the app doesn't care if the router is Cisco or Fortinet; it just looks at standardized data.

### Step 4: The Analysis Engine (`backend/app/analysis/engine.py`)
* **What it does:** This is the heart of the security audit. The engine takes the `NormalizedConfig` and runs it through a massive list of Rules (Management Rules, Boundary Rules, Crypto Rules, Logging Rules).
* **How rules work:** A rule might say: *"Look at the standardized config. Is SNMPv2 enabled? If yes, generate a High Severity Finding."*
* **Scoring:** After all rules are run, the engine calculates a final Security Score (0 to 100) based on how many Critical, High, Medium, and Low vulnerabilities were found.

### Step 5: AI Explanation & Remediation (`backend/app/ai/`)
* **What it does:** When a user clicks on a specific finding in the UI (e.g., "Telnet is enabled"), the backend calls the Google Gemini API. 
* **The Magic:** We feed the AI the exact lines of code that violated the rule, and ask it to:
  1. Explain *why* it's bad in plain English.
  2. Generate the exact commands (for that specific vendor) to fix the issue.

### Step 6: The Frontend (`frontend/src/`)
* **What it does:** The React frontend receives the final JSON report from the backend and paints it on the screen. It builds the beautiful dashboard, the score gauge, and the lists of vulnerabilities mapped to NIST and CIS benchmarks.

---

## 3. Directory Breakdown (Where to find what)

If a judge asks you to show them the code for a specific feature, here is where you look:

* **`backend/app/api/`**: The REST API routes. Show them this if they ask about how the frontend and backend talk.
* **`backend/app/parsers/`**: Show them this if they ask how you parse complex network configurations. 
* **`backend/app/controls/`** and **`backend/app/facts/`**: Show them this if they ask about your security logic and how you detect vulnerabilities (controls judge vendor-neutral security facts).
* **`backend/app/ai/`**: Show them this if they ask how the LLM (Gemini) integration works.
* **`frontend/src/components/`**: Show them this if they ask about the UI, charts, and dashboard structure.

---

## 4. Tech Stack Justification (Why we chose these tools)

Judges love asking "Why did you use X instead of Y?"

* **Backend: Python & FastAPI**
  * *Why?* Python is the absolute best language for text processing and networking. FastAPI is incredibly fast, modern, and auto-generates API documentation.
* **Frontend: React & Vite**
  * *Why?* React allows us to build complex, interactive dashboards (like expanding accordion menus for findings). Vite makes the development server blindingly fast.
* **AI: Google Gemini API**
  * *Why?* Gemini provides excellent reasoning capabilities for analyzing text/code. We use it specifically for *explaining* and *remediating*—but importantly, our core security detection relies on our own deterministic Python rules, so the app still works even if the AI is offline.
* **Architecture Pattern: Normalization Pipeline**
  * *Why?* By normalizing Cisco and Fortinet configs into a single standard model, we only have to write our security rules *once*. If we want to add Palo Alto firewalls later, we just write one new parser, and all our security rules automatically work for it!

---

## 5. Potential Questions from Judges (And how to answer)

**Q: "Does this upload real configurations to the cloud? Isn't that a security risk?"**
**A:** "For the prototype, yes, it processes files on our backend. However, because our core detection engine is written in standard Python, the entire backend can easily be deployed *on-premise* within a highly secure, air-gapped network. The AI explanation is strictly an opt-in feature."

**Q: "What if the AI hallucinates a bad fix command?"**
**A:** "That is a great question. We designed the architecture to handle this. The AI only *recommends* fixes. It never applies them directly to the live device. We also include a 'Verify Fix' feature where the user can run the generated patch through our engine again to prove it resolves the issue before they apply it in real life."

**Q: "Why didn't you just use AI to parse the configuration instead of writing custom Parsers?"**
**A:** "AI is non-deterministic; it can be inconsistent. Network security requires 100% accuracy. We use custom Python parsers and deterministic rules to guarantee we *always* find the vulnerability. We only use AI where it shines: translating that technical finding into human-readable explanations and generating custom remediation scripts."
