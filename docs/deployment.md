# Deployment Strategy

*(Status: Local hackathon deployment is supported. Production deployment is not yet implemented.)*

Since this is a hackathon project, our primary goal is a smooth demo for the judges. We do **not** plan to deploy this to a production cloud environment (AWS/GCP) right now.

## The Hackathon Deployment

We will run the entire stack locally on a laptop for the final presentation.

* **Backend:** Uvicorn running on `localhost:8000`. Configure it with `backend/.env`, copied from `backend/.env.example`.
* **Frontend:** Vite dev server running on `localhost:5173`. `VITE_API_BASE_URL` in `frontend/.env` must point at the backend.
* **Storage:** Scan results are kept in memory and disappear when the backend restarts. Learned adaptive mappings persist in SQLite (`backend/data/adaptive.db`).
* **AI:** Optional live calls to the Groq API. The scanner still works without network access or a key. Check the Groq daily quota before a demo: keys in the same organization share it, and once it is used up unknown-vendor lines show "AI unavailable".

## Future Production Considerations (Out of Scope)
If we were to take this to production:
1. Containerize backend and frontend using Docker.
2. Add a database such as PostgreSQL for persistent scan storage.
3. Deploy to a managed service like AWS Fargate or Google Cloud Run.
4. Implement proper user authentication and RBAC, including on the Training endpoints, so companies can isolate their scan data.
5. Restrict CORS, which is currently open to all origins.
