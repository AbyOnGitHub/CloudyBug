"""
Convenient entrypoint to run the FastAPI Prowler LocalStack service.
Usage:
    python run.py
"""
import uvicorn
from backend.core.config import settings

if __name__ == "__main__":
    print(f"Starting {settings.PROJECT_NAME} on http://{settings.HOST}:{settings.PORT}")
    print(f"Target LocalStack Endpoint: {settings.LOCALSTACK_ENDPOINT}")
    print(f"Interactive API Docs: http://localhost:{settings.PORT}/docs")
    print(f"Dashboard UI: http://localhost:{settings.PORT}/")
    uvicorn.run("backend.api.main:app", host=settings.HOST, port=settings.PORT, reload=True)
