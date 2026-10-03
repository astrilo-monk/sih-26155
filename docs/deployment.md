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
* Set `LIVE_COLLECTION_ENABLED=false` on any internet-reachable deployment. It defaults to on, which is right for an operator running this on their own network, but the endpoint opens SSH sessions to the hosts it is given -on a public host that is a pivot into whatever network the backend can see. If you do leave it on, pair it with `API_KEY` and a restricted `CORS_ORIGINS`.
* `LIVE_COLLECTION_NETWORKS` defaults to `private`, which is what stops the collection endpoint being a server-side request forgery: a host is resolved and refused unless it is RFC1918 or loopback, and link-local is refused outright because that is the cloud metadata address. Do not set it to `any` on a public host.

* Set `DATABASE_URL` on any host that loses its disk on restart, or everything administrators taught is lost.
* Set `SUPABASE_URL` and `SUPABASE_ANON_KEY` on a public instance, so one visitor cannot list what another taught
  (see Accounts below).

## Accounts (Supabase Auth)

1. In the Supabase project: Authentication > Sign In / Providers > Email on. Authentication > URL Configuration:
   **Site URL** = the deployed frontend URL, and add it under Redirect URLs too. Otherwise the confirmation email
   links to `localhost` and sign-up breaks in production while working locally.
2. On the backend host set `SUPABASE_URL` and `SUPABASE_ANON_KEY` (Project Settings > API). Never the service_role
   key. The frontend reads both from `GET /api/account/config`, so nothing is set on the frontend.
3. The first start runs migration 7 on the database (`owner_id` on `learned_mappings` and `rejected_lines`).
   Entries taught before accounts existed are then hidden from everyone. To keep them, sign up, copy your user id
   (Authentication > Users) and run in the SQL editor:
   `UPDATE learned_mappings SET owner_id = 'user:<your id>' WHERE owner_id = '' AND source = 'runtime';`

A guest's taught knowledge goes to the SQLite file on the backend's own disk. On Render's free tier that disk is
wiped when the service spins down after 15 minutes without traffic, or on any redeploy.

## Checking production behaviour before you deploy

Most "works locally, breaks in production" problems come from one of these differences. Check each before merging.

| Locally | In production | How to check locally |
|---|---|---|
| Vite dev server (`npm run dev`) | the built bundle | `npm run build && npm run preview`: the same files Render serves, on port 4173 |
| `VITE_API_BASE_URL` from `frontend/.env` | baked in at build time from the host's env | `VITE_API_BASE_URL=https://<backend>/api npm run build`; a variable changed on the host needs a rebuild |
| `uvicorn --reload`, your venv | a fresh install from `requirements.txt` | new venv, `pip install -r requirements.txt`, `uvicorn app.main:app` with no `--reload` |
| `backend/.env` | the host's environment variables | compare the two lists by name; a setting only in `.env` is missing in production |
| same origin family, CORS `*` | two different origins | set `CORS_ORIGINS` locally to `http://localhost:4173` and use the preview build |
| disk kept | disk wiped on spin-down or deploy | stop the backend, delete `backend/data/adaptive.db`, start it again |
| always awake | first request after sleep takes about a minute | open the site after 15 idle minutes; the UI must say it is waiting, not fail |
| Supabase redirect to `localhost` | must redirect to the deployed URL | Site URL and Redirect URLs in Supabase (Accounts, step 1) |

Then test the deployed branch itself before it replaces production: a second Render web service and static site
that deploy this branch, pointed at a **second Supabase project** (free), so migrations and test sign-ups never
touch the real database. Render's logs (service > Logs) show the backend's errors; the browser's DevTools Network
tab shows which request failed and its status.
