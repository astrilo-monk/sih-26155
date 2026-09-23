# Deployment Strategy

*(Status: Local hackathon deployment is supported. Production deployment is not yet implemented.)*

Since this is a hackathon project, our primary goal is a smooth demo for the judges. We do **not** plan to deploy this to a production cloud environment (AWS/GCP) right now.

## The Hackathon Deployment

We will run the entire stack locally on a laptop for the final presentation.

* **Backend:** Uvicorn running on `localhost:8000`. Configure it with `backend/.env`, copied from `backend/.env.example`.
* **Frontend:** Vite dev server running on `localhost:5173`. `VITE_API_BASE_URL` in `frontend/.env` must point at the backend.
* **Storage:** Scan results are kept in memory and disappear when the backend restarts; uploads are never written to disk. Recognizers, learned mappings, rejected lines (redacted) and the AI judge cache persist in SQLite (`backend/data/adaptive.db`), or in Postgres when `DATABASE_URL` is set -use that (e.g. a Supabase Session pooler URI) on a host whose disk is wiped on restart, such as Render's free tier; the shipped seed recognizers are loaded into it automatically on first use, so a fresh deployment needs no setup step for them. The UI keeps scan summaries in browser storage.
* **AI:** Optional live calls to the Groq API. The scanner still works without network access or a key. Check the Groq daily quota before a demo: keys in the same organization share it, and once it is used up the AI judge is skipped and controls keep their deterministic and heuristic results.

## Future Production Considerations (Out of Scope)
If we were to take this to production:
1. Containerize backend and frontend using Docker.
2. Add a database such as PostgreSQL for persistent scan storage.
3. Deploy to a managed service like AWS Fargate or Google Cloud Run.
4. Replace the single shared `API_KEY` with user authentication and RBAC, including on the adaptive (`/api/adaptive/*`) endpoints, so companies can isolate their scan data.

## Hardening an exposed instance today

* Set `API_KEY` in `backend/.env`: every `/api` request then needs an `X-API-Key` header or gets `401`. `/health` stays open. The bundled frontend does not send this header, so only set it for API-only use or behind a proxy that adds it.
* Set `CORS_ORIGINS` to the frontend's origin(s), comma-separated, instead of the default `*`.
* Leave `LIVE_COLLECTION_ENABLED` off unless the backend is meant to reach devices itself. It opens SSH sessions to the hosts it is given, so on an internet-reachable deployment it is a pivot into whatever network the backend can see -pair it with `API_KEY` and a restricted `CORS_ORIGINS` if you do enable it.
* Set `DATABASE_URL` on any host that loses its disk on restart, or everything administrators taught is lost.
