# 使用缓存版本的配置管理器
from copy import deepcopy
from typing import Any

from ..config.cached_config_manager import claude_config_manager


def _clone_if_mutable(value: Any) -> Any:
    """Return a safe copy for mutable configuration structures."""
    if isinstance(value, (dict, list, set)):
        return deepcopy(value)
    return value


def get_active_config():
    """Safely expose the active configuration identifier."""
    return _clone_if_mutable(claude_config_manager.active_config)


def get_configs():
    """Return a defensive copy of all configurations."""
    return deepcopy(claude_config_manager.configs)
