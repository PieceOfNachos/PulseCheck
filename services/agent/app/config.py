"""Agent service configuration, read from the environment only."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/pulsecheck")
    mongo_db: str = os.getenv("MONGO_DB", "pulsecheck")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-secret-change-me")
    port: int = int(os.getenv("AGENT_PORT", "3004"))

    # LLM — "fake" uses the scripted offline model (tests, CI, no API key)
    llm_provider: str = os.getenv("AGENT_LLM", "anthropic")  # anthropic | fake
    model: str = os.getenv("AGENT_MODEL", "claude-opus-5-5")
    effort: str = os.getenv("AGENT_EFFORT", "medium")

    # RAG — QDRANT_URL=":memory:" runs an in-process store
    qdrant_url: str = os.getenv("QDRANT_URL", "http://localhost:6333")
    embed_model: str = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
    runbooks_dir: str = os.getenv(
        "RUNBOOKS_DIR", os.path.join(os.path.dirname(__file__), "..", "runbooks")
    )

    # Governance
    max_tool_calls: int = int(os.getenv("AGENT_MAX_TOOL_CALLS", "4"))
    token_budget: int = int(os.getenv("AGENT_TOKEN_BUDGET", "60000"))
    untrusted_max_chars: int = int(os.getenv("AGENT_UNTRUSTED_MAX_CHARS", "2048"))
    allow_private_targets: bool = os.getenv("AGENT_ALLOW_PRIVATE_TARGETS", "false") == "true"


settings = Settings()
