# Development Setup

How to get the project running on your local machine.

## Prerequisites
* Python 3.11+
* Node.js v18+
* A Google Gemini API key only if AI features are needed

## Backend Setup (Available Now)

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
4. Create a `.env` file in the `backend/` directory:
   ```
   GEMINI_API_KEY=your_key_here
   ```
5. Run the FastAPI dev server:
   ```bash
   uvicorn app.main:app --reload
   ```

## Frontend Setup

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

The frontend normally opens at `http://localhost:5173` and connects to `http://localhost:8000/api`.

To use another backend URL, set `VITE_API_BASE_URL` before starting Vite.
