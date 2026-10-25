from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Limits(BaseModel):
    max_rps: float = 5.0
    request_timeout_sec: float = 15.0
    scan_timeout_sec: float = 180.0


class HttpConfig(BaseModel):
    user_agent: str = "vuln-agent/0.1 (+authorized-scan)"
    follow_redirects: bool = True
    max_redirects: int = 5


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULN_AGENT_", extra="ignore")

    config: str = "config/default.yaml"
    host: str = "0.0.0.0"
    port: int = 8000
    mongo_uri: Optional[str] = None
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    enabled_agents: List[str] = Field(default_factory=lambda: ["recon", "reporter"])
    limits: Limits = Field(default_factory=Limits)
    http: HttpConfig = Field(default_factory=HttpConfig)

    @classmethod
    def load(cls, config_path: str | None = None) -> "Settings":
        base = cls()
        path = Path(config_path or base.config)
        if not path.is_file():
            alt = Path.cwd() / path
            path = alt if alt.is_file() else path
        data = {}
        if path.is_file():
            data = yaml.safe_load(path.read_text()) or {}
        limits = Limits(**(data.get("limits") or {}))
        http = HttpConfig(**(data.get("http") or {}))
        return cls(
            config=str(path),
            enabled_agents=list(data.get("enabled_agents") or ["recon", "reporter"]),
            limits=limits,
            http=http,
            host=base.host,
            port=base.port,
            mongo_uri=base.mongo_uri,
            cors_origins=base.cors_origins,
        )
