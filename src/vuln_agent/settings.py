from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Keys providers read via os.getenv (not VULN_AGENT_* settings fields)
_LLM_ENV_KEYS = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "VULN_AGENT_GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
    "VULN_AGENT_ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "VULN_AGENT_OPENAI_API_KEY",
    "VULN_AGENT_GEMINI_MODEL",
    "VULN_AGENT_CLAUDE_MODEL",
    "VULN_AGENT_OPENAI_MODEL",
)


def _export_llm_keys_from_dotenv(path: Path) -> None:
    """Ensure API keys in .env are visible to LLM providers via os.environ."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key not in _LLM_ENV_KEYS:
            continue
        val = val.strip().strip("'").strip('"')
        if val and key not in os.environ:
            os.environ[key] = val


class Limits(BaseModel):
    max_rps: float = 5.0
    request_timeout_sec: float = 15.0
    scan_timeout_sec: float = 180.0


class HttpConfig(BaseModel):
    user_agent: str = "vuln-agent/0.1 (+authorized-scan)"
    follow_redirects: bool = True
    max_redirects: int = 5


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VULN_AGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    config: str = "config/default.yaml"
    host: str = "0.0.0.0"
    port: int = 8000
    mongo_uri: Optional[str] = None
    redis_url: Optional[str] = None
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    enabled_agents: List[str] = Field(default_factory=lambda: ["recon", "reporter"])
    limits: Limits = Field(default_factory=Limits)
    http: HttpConfig = Field(default_factory=HttpConfig)
    llm: Dict[str, Any] = Field(
        default_factory=lambda: {
            "lead": "claude",
            "adapt": "gemini-flash",
            "reporter": "claude",
            "fallback": "openai",
        }
    )

    @classmethod
    def load(cls, config_path: str | None = None) -> "Settings":
        _export_llm_keys_from_dotenv(Path.cwd() / ".env")
        _export_llm_keys_from_dotenv(Path(__file__).resolve().parents[2] / ".env")
        base = cls()
        path = Path(config_path or base.config)
        if not path.is_file():
            alt = Path.cwd() / path
            path = alt if alt.is_file() else path
        data: Dict[str, Any] = {}
        if path.is_file():
            data = yaml.safe_load(path.read_text()) or {}
        limits = Limits(**(data.get("limits") or {}))
        http = HttpConfig(**(data.get("http") or {}))
        llm = dict(base.llm)
        llm.update(data.get("llm") or {})
        return cls(
            config=str(path),
            enabled_agents=list(data.get("enabled_agents") or ["recon", "reporter"]),
            limits=limits,
            http=http,
            host=base.host,
            port=base.port,
            mongo_uri=base.mongo_uri,
            redis_url=base.redis_url,
            cors_origins=base.cors_origins,
            llm=llm,
        )
