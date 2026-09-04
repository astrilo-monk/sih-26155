# Deployment Strategy

*(Status: Local hackathon deployment is supported. Production deployment is not yet implemented.)*

Since this is a hackathon project, our primary goal is a smooth demo for the judges. We do **not** plan to deploy this to a production cloud environment (AWS/GCP) right now. 

## The Hackathon Deployment

We will run the entire stack locally on a laptop for the final presentation. 

* **Backend:** Uvicorn running on `localhost:8000`
* **Frontend:** Vite dev server running on `localhost:5173`
* **Storage:** In-memory scan store; results disappear when the backend restarts
* **AI:** Optional live calls to the Gemini API. The scanner still works without network access or a key.

## Future Production Considerations (Out of Scope)
If we were to take this to production:
1. Containerize backend and frontend using Docker.
2. Add a database such as PostgreSQL for persistent scan storage.
3. Deploy to a managed service like AWS Fargate or Google Cloud Run.
4. Implement proper user authentication and RBAC so companies can isolate their scan data.
