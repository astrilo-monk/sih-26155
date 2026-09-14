# Development Setup

How to get the project running on your local machine.

## Prerequisites
* Python 3.10+
* Node.js v18+
* A Groq API key, only if AI features are needed (explanations, chat, and AI judge proposals for unknown-vendor configs)

## Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create `backend/.env` from the example and add your key(s):
   ```bash
   cp .env.example .env
   ```
   All settings are optional. See the comments in `backend/.env.example`:
   * `GROQ_API_KEY`, `GROQ_API_KEY_1` .. `GROQ_API_KEY_4`: tried in that order. The next key is used when one is rate-limited (429) or rejected (401/403/404). Keys from the same Groq organization share one daily quota, so extra keys from the same account do not add quota.
   * `ADAPTIVE_DB_PATH`: SQLite file for recognizers, learned mappings, rejected lines and the AI judge cache (default `backend/data/adaptive.db`, created automatically). Recognizers survive backend restarts through this file.
   * `AI_JUDGE_MAX_CALLS_PER_SCAN`: AI judge requests per scan for unknown-vendor configs (default `2`; cache hits are free).
   * `VENDOR_PARSE_COVERAGE_THRESHOLD`: share of lines that must follow the detected vendor's grammar before its parser is trusted (default `0.7`).
   * `ADAPTIVE_AI_FOR_KNOWN_VENDORS`: legacy, default `false` — send lines the Cisco/FortiGate parsers do not read to the line interpreter; results only reach the review queue.
5. Run the FastAPI dev server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## Frontend Setup

Open a second terminal:

```powershell
cd frontend
cp .env.example .env
npm install
npm run dev
```

The frontend opens at `http://localhost:5173` and calls the backend at `VITE_API_BASE_URL` (default `http://localhost:8000/api`).

If you run uvicorn on a different port, update `VITE_API_BASE_URL` in `frontend/.env` and restart Vite. Vite only reads `.env` at startup.
