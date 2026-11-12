"""5STONES — FastAPI main application."""
from __future__ import annotations
import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv

load_dotenv()

from backend.utils.access_control import local_development_request_allowed, reset_workspace_context, set_workspace_context, validate_enterprise_security_config
from backend.utils.audit import reset_audit_actor, reset_audit_workspace, set_audit_actor, set_audit_workspace
from backend.utils.request_limits import MAX_HTTP_REQUEST_BYTES, RequestBodyLimitMiddleware
from backend.utils.storage import (
    DfdRevisionConflict,
    ProjectNotFoundError,
    ProjectRevisionConflict,
    RevisionConflict,
)

from backend.routers import projects, analysis, artifacts, export, settings, dfd, ux_telemetry, auth

app = FastAPI(
    title="5STONES API",
    description="AI-Assisted Threat Modeling Platform",
    version="1.0.0-mvp",
    docs_url=None if os.getenv("APP_ENV", "").strip().casefold() == "enterprise" else "/api/docs",
    redoc_url=None if os.getenv("APP_ENV", "").strip().casefold() == "enterprise" else "/api/redoc",
    openapi_url=None if os.getenv("APP_ENV", "").strip().casefold() == "enterprise" else "/api/openapi.json",
)


@app.exception_handler(RevisionConflict)
@app.exception_handler(DfdRevisionConflict)
@app.exception_handler(ProjectRevisionConflict)
async def project_revision_conflict_handler(
    _request,
    exc: RevisionConflict | DfdRevisionConflict | ProjectRevisionConflict,
):
    return JSONResponse(
        status_code=409,
        content={
            "detail": {
                "message": "Project revision conflict; reload the current state and retry the edit.",
                "resource": (
                    "dfd" if isinstance(exc, DfdRevisionConflict)
                    else "project" if isinstance(exc, ProjectRevisionConflict)
                    else "report"
                ),
                "expected_revision": exc.expected_revision,
                "current_revision": exc.current_revision,
            }
        },
    )


@app.exception_handler(ProjectNotFoundError)
async def deleted_project_resource_handler(_request, _exc: ProjectNotFoundError):
    return JSONResponse(status_code=404, content={"detail": "Project not found"})


@app.on_event("startup")
async def validate_security_configuration():
    validate_enterprise_security_config()


@app.middleware("http")
async def audit_request_actor(request, call_next):
    """Keep verified request identity as the default audit actor."""
    actor_token = set_audit_actor("anonymous")
    workspace_token = set_audit_workspace(None)
    context_token = set_workspace_context(None)
    try:
        if not local_development_request_allowed(request):
            return JSONResponse(status_code=403, content={"detail": "Local development access is restricted to loopback clients"})
        return await call_next(request)
    finally:
        reset_workspace_context(context_token)
        reset_audit_workspace(workspace_token)
        reset_audit_actor(actor_token)


cors_origins = [item.strip().rstrip("/") for item in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if item.strip()]

app.add_middleware(
    RequestBodyLimitMiddleware,
    max_bytes=MAX_HTTP_REQUEST_BYTES,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Workspace-ID", "X-CSRF-Token"],
)

# Register routers
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(analysis.router)
app.include_router(artifacts.router)
app.include_router(export.router)
app.include_router(settings.router)
app.include_router(dfd.router)
app.include_router(ux_telemetry.router)

# Serve frontend static files
frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return FileResponse(str(frontend_dir / "logo.png"))

    @app.get("/")
    async def root():
        return FileResponse(str(frontend_dir / "index.html"))

    @app.get("/{page}.html")
    async def serve_page(page: str):
        page_file = frontend_dir / f"{page}.html"
        if page_file.exists():
            return FileResponse(str(page_file))
        return FileResponse(str(frontend_dir / "index.html"))


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0-mvp"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", 8000)),
        reload=True,
    )
