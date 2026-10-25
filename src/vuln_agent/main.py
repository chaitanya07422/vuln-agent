from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from vuln_agent.api.routes_scans import router as scans_router
from vuln_agent.core.lead import LeadRunner
from vuln_agent.playbook_loader import default_playbook_store
from vuln_agent.settings import Settings
from vuln_agent.store.mongo import build_store


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    store = build_store(settings.mongo_uri)
    playbooks = default_playbook_store(settings.config)
    lead = LeadRunner(settings, store, playbooks=playbooks)

    app = FastAPI(title="vuln-agent", version="0.1.0")
    app.state.settings = settings
    app.state.store = store
    app.state.lead = lead
    app.state.playbooks = playbooks
    app.include_router(scans_router)

    web_dir = Path(__file__).resolve().parent / "web"
    if web_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

        @app.get("/")
        async def ui() -> FileResponse:
            return FileResponse(web_dir / "index.html")

    @app.get("/health")
    async def health() -> dict:
        return {
            "ok": True,
            "enabled_agents": settings.enabled_agents,
            "playbooks": sorted(playbooks._cache.keys()),
            "store": type(store).__name__,
        }

    return app


def run() -> None:
    import uvicorn

    settings = Settings.load()
    uvicorn.run(
        "vuln_agent.main:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        reload=False,
    )


app = create_app()
