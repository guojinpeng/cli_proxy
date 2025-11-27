#!/usr/bin/env python3
"""
Claude服务控制器 - 使用优化后的基础类
"""
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ..core.base_proxy import BaseServiceController
from ..config.cached_config_manager import claude_config_manager

DEFAULT_PORT = 3210


class ClaudeController(BaseServiceController):
    """
    Claude服务控制器
    """

    def __init__(self):
        super().__init__(
            service_name="claude",
            port=DEFAULT_PORT,
            config_manager=claude_config_manager,
            proxy_module_path="src.claude.proxy",
        )
        # 为了兼容性，设置旧的PID文件名
        self.pid_file = self.config_dir / "claude_code_proxy.pid"


_controller_instance: Optional[ClaudeController] = None


def _get_controller() -> ClaudeController:
    """Lazily create and reuse a controller instance."""
    global _controller_instance
    if _controller_instance is None:
        _controller_instance = ClaudeController()
    return _controller_instance


# 兼容性函数（保持原有接口）
def get_pid():
    return _get_controller().get_pid()


def is_running():
    return _get_controller().is_running()


def start(port: Optional[int] = None):
    return _get_controller().start(port=port)


def stop():
    return _get_controller().stop()


def restart(port: Optional[int] = None):
    return _get_controller().restart(port=port)


def status():
    return _get_controller().status()


# 兼容旧版本的函数
def start_daemon(port: int = DEFAULT_PORT):
    """启动守护进程（兼容旧接口）"""
    return start(port=port)


def stop_handler(signum, frame):
    """停止信号处理函数（兼容旧接口）"""
    stop()


# 导出配置目录等路径（为了兼容性）
config_dir = Path.home() / ".clp/run"
data_dir = Path.home() / ".clp/data"


def set_active_config(config_name: str) -> bool:
    """设置激活配置"""
    return claude_config_manager.set_active_config(config_name)


def list_configs() -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """列出所有配置，返回配置映射和当前激活配置名"""
    configs = claude_config_manager.configs
    active = claude_config_manager.active_config
    return configs, active


def __getattr__(name: str):
    """兼容旧代码访问 controller/PID_FILE/LOG_FILE 等属性"""
    controller = _get_controller()
    if name == "controller":
        return controller
    if name == "PID_FILE":
        return controller.pid_file
    if name == "LOG_FILE":
        return controller.log_file
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
