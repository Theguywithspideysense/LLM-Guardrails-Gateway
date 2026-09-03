"""Shared configuration for the API, guards, and Ollama clients."""
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
from limits import parse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

def positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value

def boolean(name: str, default: bool) -> bool:
    value = os.getenv(name, str(default)).lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"true", "1"}

@dataclass(frozen=True)
class Settings:
    model: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    ollama_timeout: int = positive_int("OLLAMA_TIMEOUT_SECONDS", 120)
    rate_limit: str = os.getenv("RATE_LIMIT", "10/minute")
    max_input_length: int = positive_int("MAX_INPUT_LENGTH", 8000)
    max_line_count: int = positive_int("MAX_LINE_COUNT", 200)
    max_body_bytes: int = positive_int("MAX_BODY_BYTES", 65536)
    max_output_length: int = positive_int("MAX_OUTPUT_LENGTH", 32000)
    max_concurrent_requests: int = positive_int("MAX_CONCURRENT_REQUESTS", 2)
    semantic_enabled: bool = boolean("SEMANTIC_ENABLED", True)
    admin_key: str = os.getenv("GATEWAY_ADMIN_KEY", "")
    log_dir: Path = Path(os.getenv("LOG_DIR", str(PROJECT_ROOT / "logs")))

    def __post_init__(self):
        parse(self.rate_limit)
        if not self.model.strip():
            raise ValueError("OLLAMA_MODEL must not be empty")
        if not self.ollama_host.startswith(("http://", "https://")):
            raise ValueError("OLLAMA_HOST must be an HTTP(S) URL")

settings = Settings()
