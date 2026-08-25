# Key Decisions

Here are the major technical and design decisions we've made for this hackathon project, and why.

## 1. Vendor Selection: Cisco IOS + FortiGate
**Why:** Cisco IOS has massive market share and standard text-based configs that are well-documented. FortiGate gives us a firewall context, proving our platform handles both routing and edge security. Both are impressive for the demo and distinct enough to prove the value of our normalized model.

## 2. Tech Stack: Python/FastAPI + React + SQLite + Gemini
**Why:** 
- **Python/FastAPI**: Fastest way to build a backend, great text processing/regex support, and easy to integrate with AI SDKs.
- **React**: Standard, easy to build a clean dashboard quickly.
- **SQLite**: No need to spin up Postgres for a hackathon. Easy to reset and demo.
- **Gemini**: Fast, good context window for configs, and required by the hackathon prompt.

## 3. The Normalized Model Approach
**Why:** We realized that writing security rules specific to every vendor would be a nightmare. By converting everything to a standard JSON-like object (e.g., a generic `Interface` object with `is_up`, `ip_address`, `has_acl`), we only have to write the security rules engine once.

## 4. Deterministic Rules > AI for Detection
**Why:** AI hallucinates. If we use an LLM to *detect* misconfigurations, it might miss obvious things or invent vulnerabilities. We decided to use hardcoded, deterministic rules against the normalized data for **detection** to guarantee accuracy, and only use AI for **explanations and remediation**.

## 5. Penalty-based Scoring Algorithm
**Why:** We need a way to grade configs. We decided on a starting score of 100, subtracting points based on findings:
- Critical: -12 points
- High: -6 points
- Medium: -3 points
- Low: -1 point
(Bounded at 0, obviously). Easy to implement and understand.
