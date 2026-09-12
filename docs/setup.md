# Development Setup

How to get the project running on your local machine.

## Prerequisites
* Python 3.11+
* Node.js v18+
* A Groq API key, only if AI features are needed (explanations, chat, and AI interpretation of unknown-vendor configs)

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
   * `ADAPTIVE_DB_PATH`: SQLite file for learned mappings (default `backend/data/adaptive.db`, created automatically).
   * `ADAPTIVE_AI_FOR_KNOWN_VENDORS`: also send unparsed Cisco/FortiGate lines to the AI (default `false`).
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
