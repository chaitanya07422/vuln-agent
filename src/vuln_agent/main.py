from __future__ import annotations

from fastapi import FastAPI

from vuln_agent.api.routes_scans import router as scans_router
from vuln_agent.core.lead import LeadRunner
from vuln_agent.settings import Settings
from vuln_agent.store.memory import MemoryScanStore


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    store = MemoryScanStore()
    lead = LeadRunner(settings, store)

    app = FastAPI(title="vuln-agent", version="0.1.0")
    app.state.settings = settings
    app.state.store = store
    app.state.lead = lead
    app.include_router(scans_router)

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True, "enabled_agents": settings.enabled_agents}

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
