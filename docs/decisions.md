# Key Decisions

Here are the major technical and design decisions we've made for this hackathon project, and why.

## 1. Vendor Selection: Cisco IOS + FortiGate
**Why:** Cisco IOS has massive market share and standard text-based configs that are well-documented. FortiGate gives us a firewall context, proving our platform handles both routing and edge security. Both are impressive for the demo and distinct enough to prove the value of our normalized model.

## 2. Tech Stack: Python/FastAPI + React + In-Memory Storage + Gemini
**Why:** 
- **Python/FastAPI**: Fastest way to build a backend, great text processing/regex support, and easy to integrate with AI SDKs.
- **React**: Standard, easy to build a clean dashboard quickly.
- **In-memory storage**: We kept the prototype simple and avoided adding a database before the core scan flow was stable. Results currently disappear when the backend restarts.
- **Gemini**: Fast, good context window for configs, and required by the hackathon prompt.

## 3. The Normalized Model Approach
**Why:** We realized that writing security rules specific to every vendor would be a nightmare. By converting everything to a shared dataclass model with interfaces, services, ACLs, firewall policies, VPN data, and source line numbers, we only have to write the security rules engine once.

## 4. Deterministic Rules > AI for Detection
**Why:** AI can miss obvious things or invent vulnerabilities. We use hardcoded, deterministic rules against the normalized data for **detection**. Gemini is used for explanations, summaries, and chat, while remediation commands come from deterministic vendor-specific templates.

## 5. Penalty-based Scoring Algorithm
**Why:** We need a way to grade configs. We decided on a starting score of 100, subtracting points based on findings:
- Critical: -12 points
- High: -6 points
- Medium: -3 points
- Low: -1 point
(Bounded at 0, obviously). Easy to implement and understand.

## 6. AI Is Not Used for Detection or Commands

The scanner uses deterministic Python rules for detection. Gemini is optional and is used for explanations, summaries, and chat. Remediation commands come from vendor-specific templates because an invented command could disrupt real network equipment.
