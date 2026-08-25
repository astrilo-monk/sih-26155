# Deployment Strategy

*(Status: Planned for final demo)*

Since this is a hackathon project, our primary goal is a smooth demo for the judges. We do **not** plan to deploy this to a production cloud environment (AWS/GCP) right now. 

## The Hackathon Deployment

We will run the entire stack locally on a laptop for the final presentation. 

* **Backend:** Uvicorn running on `localhost:8000`
* **Frontend:** Vite dev server running on `localhost:5173`
* **Database:** Local SQLite file (`app.db`)
* **AI:** Live calls to the Gemini API over the conference WiFi (we should have a backup hotspot ready).

## Future Production Considerations (Out of Scope)
If we were to take this to production:
1. Containerize backend and frontend using Docker.
2. Swap SQLite for PostgreSQL.
3. Deploy to a managed service like AWS Fargate or Google Cloud Run.
4. Implement proper user authentication and RBAC so companies can isolate their scan data.
