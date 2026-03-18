from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import artifacts, bundle, compare, health, runs, stream, timeline, prognostics, trends


def create_app() -> FastAPI:
    app = FastAPI(
        title="TestPulse Run Viewer API",
        version="0.2.0",
        description="Thin API for Run Viewer MVP: bundle, timeline, health, prognostics.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(runs.router)
    app.include_router(bundle.router)
    app.include_router(artifacts.router)
    app.include_router(timeline.router)
    app.include_router(health.router)
    app.include_router(prognostics.router)
    app.include_router(trends.router)
    app.include_router(compare.router)
    app.include_router(stream.router)
    return app


app = create_app()


def main() -> None:
    import uvicorn
    uvicorn.run(
        "testpulse.api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
