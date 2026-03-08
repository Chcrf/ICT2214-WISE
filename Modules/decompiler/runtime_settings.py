import os
import sys
from typing import Any, Dict

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from wise_config import CONFIG as WISE_CONFIG


def get_decompiler_config() -> Dict[str, Any]:
    """Return the centralized decompiler config mapping."""
    return WISE_CONFIG["decompiler"]


def update_decompiler_config(**kwargs: Any) -> None:
    """Apply runtime overrides to the centralized decompiler config section."""
    config = get_decompiler_config()
    for key, value in kwargs.items():
        if key in config:
            config[key] = value
