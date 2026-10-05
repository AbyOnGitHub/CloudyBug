import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.core.config import settings
from backend.api.routes import router as api_router

# Create FastAPI instance
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
    ## Prowler LocalStack Security Microservice
    Integrates the Prowler engine with LocalStack to run cloud security compliance checks.
    
    ### Key Features:
    * **Prowler SDK & LocalStack Integration**: Scans LocalStack endpoints instead of AWS.
    * **AWS Security Finding Format (ASFF)**: Captures findings in native AWS Security Hub ASFF format.
    * **Parser & Normalization Engine**: Translates ASFF findings into structured JSON objects with `severity`, `resource_id`, `resource_type`, `recommendation`, `compliance_status`.
    * **LangGraph Security Triage**: Automated agentic security posture analysis, risk scoring, and remediation plan generation.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router under /api prefix and root
app.include_router(api_router, prefix="/api")
app.include_router(api_router)  # Also expose at root /scan, /health

# Mount Frontend assets & React SPA
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
dist_dir = frontend_dir / "dist"

if dist_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_react_dashboard():
        index_file = dist_dir / "index.html"
        return FileResponse(str(index_file))

elif frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"message": "Prowler LocalStack Security Service is running. Visit /docs for API documentation."}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
