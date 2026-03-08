import os
from typing import Any, Dict


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
MODULES_DIR = os.path.join(ROOT_DIR, "Modules")
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

_cors_raw = _env_str("WISE_CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")
_cors_origins = [item.strip() for item in _cors_raw.split(",") if item.strip()]

CONFIG: Dict[str, Dict[str, Any]] = {
    "paths": {
        "root_dir": ROOT_DIR,
        "backend_dir": BACKEND_DIR,
        "modules_dir": MODULES_DIR,
        "frontend_dir": FRONTEND_DIR,
        "db_path": os.path.join(BACKEND_DIR, "wise.db"),
        "uploads_dir": os.path.join(BACKEND_DIR, "uploads"),
        "analysis_results_dir": os.path.join(BACKEND_DIR, "analysis_results"),
    },
    "backend": {
        "host": _env_str("WISE_BACKEND_HOST", "0.0.0.0"),
        "port": _env_int("WISE_BACKEND_PORT", 8000),
        "reload": _env_bool("WISE_BACKEND_RELOAD", True),
        "cors_origins": _cors_origins,
    },
    "analyzer": {
        "yaragen_image": _env_str("YARAGEN_IMAGE", "yaragen:latest"),
        "yaragen_timeout": _env_int("YARAGEN_TIMEOUT", 300),
        "wasm_decompile_timeout": _env_int("WASM_DECOMPILE_TIMEOUT", 60),
        "worker_idle_sleep_seconds": _env_float("ANALYSIS_WORKER_IDLE_SLEEP", 2.0),
        "worker_active_sleep_seconds": _env_float("ANALYSIS_WORKER_ACTIVE_SLEEP", 0.5),
    },
    "threat_intel": {
        "opencti_url": _env_str("OPENCTI_URL", "https://opencti.netmanageit.com/graphql"),
        "vt_post_to_get_delay": _env_int("VT_POST_TO_GET_DELAY", 20),
        "request_timeout": _env_int("THREAT_INTEL_REQUEST_TIMEOUT", 30),
    },
    "decompiler": {
        "provider": _env_str("WISE_PROVIDER", "openai"),
        "model": _env_str("WISE_MODEL", "gpt-4o-mini"),
        "temperature": _env_float("WISE_TEMPERATURE", 0.1),
        "symbol_batch_size": _env_int("WISE_SYMBOL_BATCH_SIZE", 12),
        "lift_batch_size": _env_int("WISE_LIFT_BATCH_SIZE", 4),
        "refine_batch_size": _env_int("WISE_REFINE_BATCH_SIZE", 8),
        "llm_max_retries": _env_int("WISE_LLM_MAX_RETRIES", 3),
        "max_prompt_tokens": _env_int("WISE_MAX_PROMPT_TOKENS", 100000),
        "allow_single_fallback": _env_bool("WISE_ALLOW_SINGLE_FALLBACK", False),
        "trust_batch_order_mapping": _env_bool("WISE_TRUST_BATCH_ORDER_MAPPING", True),
    },
    "dynan": {
        "image_tag": _env_str("DYNAN_IMAGE_TAG", "dynan"),
        "container_name": _env_str("DYNAN_CONTAINER_NAME", "dynan-analysis"),
        "stats_poll_interval": _env_int("DYNAN_STATS_POLL_INTERVAL", 2),
        "execution_timeout": _env_int("DYNAN_EXECUTION_TIMEOUT", 180),
        "container_output_dir": _env_str("DYNAN_CONTAINER_OUTPUT_DIR", "/output"),
        "archive_dirname": _env_str("DYNAN_ARCHIVE_DIRNAME", "archives"),
        "run_analysis_timeout_ms": _env_int("DYNAN_ANALYSIS_TIMEOUT_MS", 60000),
        "run_analysis_observation_time_ms": _env_int("DYNAN_ANALYSIS_OBSERVATION_MS", 60000),
    },
}
