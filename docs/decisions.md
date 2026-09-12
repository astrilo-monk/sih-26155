# Key Decisions

Here are the major technical and design decisions we've made for this hackathon project, and why.

## 1. Vendor Selection: Cisco IOS + FortiGate
**Why:** Cisco IOS has massive market share and standard text-based configs that are well-documented. FortiGate gives us a firewall context, proving our platform handles both routing and edge security. Both are impressive for the demo and distinct enough to prove the value of our normalized model.

## 2. Tech Stack: Python/FastAPI + React + In-Memory Storage + SQLite + Groq
**Why:** 
- **Python/FastAPI**: Fastest way to build a backend, great text processing/regex support, and easy to integrate with AI SDKs.
- **React**: Standard, easy to build a clean dashboard quickly.
- **In-memory storage**: We kept the prototype simple and avoided adding a database before the core scan flow was stable. Scan results currently disappear when the backend restarts.
- **SQLite**: Administrator-confirmed adaptive mappings must survive restarts, and SQLite needs no extra service.
- **Groq** (`openai/gpt-oss-120b`): Fast, supports strict JSON-schema output, and has a free tier. The project originally used Gemini; all AI calls are isolated in `backend/app/ai/client.py`, so the provider can be swapped again.

## 3. The Normalized Model Approach
**Why:** We realized that writing security rules specific to every vendor would be a nightmare. By converting everything to a shared dataclass model with interfaces, services, ACLs, firewall policies, VPN data, and source line numbers, we only have to write the security rules engine once.

## 4. Deterministic Rules > AI for Detection
**Why:** AI can miss obvious things or invent vulnerabilities. We use hardcoded, deterministic rules against the normalized data for **detection**. The AI is used for explanations, summaries, chat, and translating unfamiliar syntax into normalized fields. Remediation commands come from deterministic vendor-specific templates.

## 5. Penalty-based Scoring Algorithm
**Why:** We need a way to grade configs. We decided on a starting score of 100, subtracting points based on findings:
- Critical: -12 points
- High: -6 points
- Medium: -3 points
- Low: -1 point
(Bounded at 0, obviously). Easy to implement and understand.

## 6. AI Is Not Used for Detection or Commands

The scanner uses deterministic Python rules for detection. The AI is optional. Remediation commands come from vendor-specific templates, because an invented command could disrupt real network equipment.

## 7. Generic Adaptive Layer Instead of Per-Vendor Patches

**Why:** The problem statement asks for a vendor-agnostic engine, and writing a parser for every vendor does not scale. Unknown configs go through one generic pipeline:
1. relevance filter
2. learned mappings
3. AI interpretation
4. evidence validation
5. confidence tiers
6. Training queue

The AI may only choose fields from one shared catalog (`field_catalog.py`), must cite evidence from the line, and cannot activate rules on its own:
- **HIGH confidence** results need valid evidence before they are applied.
- **Uncertain** results wait for an administrator.

## 8. AI Never Decides the Vendor

**Why:** Vendor-specific rules (for example SSH-version checks written for Cisco) would fire wrongly if an AI guess switched them on. `device.vendor` is set only by the deterministic detector. The AI's vendor guesses are reported as *vendor evidence* for information only.
