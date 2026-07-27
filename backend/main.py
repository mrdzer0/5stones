"""5STONES — FastAPI main application."""
from __future__ import annotations
import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

load_dotenv()

from backend.routers import projects, analysis, artifacts, export, settings

app = FastAPI(
    title="5STONES API",
    description="AI-Assisted Threat Modeling Platform",
    version="1.0.0-mvp",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: restrict to app domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(projects.router)
app.include_router(analysis.router)
app.include_router(artifacts.router)
app.include_router(export.router)
app.include_router(settings.router)

# Serve frontend static files
frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

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
