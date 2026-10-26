from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from vuln_agent.api.routes_auth import router as auth_router
from vuln_agent.api.routes_billing import router as billing_router
from vuln_agent.api.routes_scans import router as scans_router
from vuln_agent.auth.guest_quota import build_guest_quota_store
from vuln_agent.auth.refresh_store import build_refresh_store
from vuln_agent.auth.users import build_user_store

from vuln_agent.core.lead import LeadRunner
from vuln_agent.llm.factory import build_llm_router
from vuln_agent.playbook_loader import default_playbook_store
from vuln_agent.settings import Settings
from vuln_agent.store.mongo import build_store


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    store = build_store(settings.mongo_uri)
    users = build_user_store(settings.mongo_uri)
    refresh_store = build_refresh_store(settings.redis_url)
    guest_quota = build_guest_quota_store(settings.redis_url)
    playbooks = default_playbook_store(settings.config)
    llm = build_llm_router(settings.llm)
    lead = LeadRunner(settings, store, playbooks=playbooks, llm=llm)

    app = FastAPI(title="vuln-agent", version="0.1.0")
    app.state.settings = settings
    app.state.store = store
    app.state.users = users
    app.state.refresh_store = refresh_store
    app.state.guest_quota = guest_quota
    app.state.oauth_states = {}
    app.state.lead = lead
    app.state.playbooks = playbooks
    app.state.llm = llm

    origins = [o.strip() for o in (settings.cors_origins or "").split(",") if o.strip()]
    if not origins:
        origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
        ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router)
    app.include_router(billing_router)
    app.include_router(scans_router)

    web_dir = Path(__file__).resolve().parent / "web"
    if web_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

        @app.get("/")
        async def ui() -> FileResponse:
            return FileResponse(web_dir / "index.html")

    @app.get("/health")
    async def health() -> dict:
        from vuln_agent.auth import google_oauth

        return {
            "ok": True,
            "enabled_agents": settings.enabled_agents,
            "playbooks": sorted(playbooks._cache.keys()),
            "store": type(store).__name__,
            "auth": {"google": google_oauth.google_configured()},
            "llm": {
                "lead": llm.provider_name("lead"),
                "adapt": llm.provider_name("adapt"),
                "reporter": llm.provider_name("reporter"),
            },
            "queue": "arq" if (settings.redis_url and settings.mongo_uri) else "in_process",
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
