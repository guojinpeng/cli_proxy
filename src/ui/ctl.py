#!/usr/bin/env python3
import os
import sys
import signal
import time
import subprocess
from pathlib import Path
from .ui_server import app, ensure_ui_security_bootstrap
from ..utils.platform_helper import is_process_running, kill_process, create_detached_process

# UI服务配置
DEFAULT_PORT = 3300
CONFIG_DIR = Path.home() / '.clp/run'
PID_FILE = CONFIG_DIR / 'ui.pid'
LOG_FILE = CONFIG_DIR / 'ui.log'

def get_pid():
    """获取当前进程的PID"""
    try:
        with open(PID_FILE, 'r') as f:
            return int(f.read().strip())
    except (IOError, ValueError):
        return None

def is_running():
    """检查进程是否正在运行"""
    pid = get_pid()
    return is_process_running(pid)

def stop_handler(signum, frame):
    """信号处理器"""
    print("收到停止信号，正在退出...")
    if PID_FILE.exists():
        PID_FILE.unlink()
    sys.exit(0)

def start_daemon(port=DEFAULT_PORT):
    """启动UI守护进程"""
    if is_running():
        print("UI服务已经在运行中")
        return None

    # 确保配置目录存在
    CONFIG_DIR.mkdir(exist_ok=True)

    # 启动前安全初始化（默认管理员、JWT密钥、启用UI鉴权）
    try:
        ensure_ui_security_bootstrap(print)
    except Exception as e:
        print(f"[auth] 启动前安全初始化失败: {e}")

    try:
        # 启动方式改为使用生产级WSGI服务器
        if sys.platform == "win32":
            # Windows 使用 waitress
            cmd = [
                sys.executable, '-m', 'waitress',
                '--host=0.0.0.0',
                f'--port={port}',
                '--threads=4',
                'src.ui.ui_server:app'
            ]
        else:
            # Unix/Linux 使用 gunicorn
            cmd = [
                sys.executable, '-m', 'gunicorn',
                '-w', '2',
                '-b', f'0.0.0.0:{port}',
                'src.ui.ui_server:app'
            ]

        with open(LOG_FILE, 'a') as log:
            proc = create_detached_process(cmd, log)
            
            # 写PID文件
            with open(PID_FILE, 'w') as f:
                f.write(str(proc.pid))

        # 等待服务启动
        time.sleep(1)

        if is_running():
            print(f"UI服务启动成功 (端口: {port})")
        else:
            print(f"UI服务服务启动失败")

    except Exception as e:
        print(f"启动UI服务失败: {e}")

def stop_daemon():
    """停止UI守护进程"""
    pid = get_pid()
    if pid is None:
        print("UI服务没有运行")
        return

    try:
        if kill_process(pid):
            if PID_FILE.exists():
                PID_FILE.unlink()
            print("UI服务已停止")
        else:
            print("停止UI服务失败")
            if PID_FILE.exists():
                PID_FILE.unlink()
    except Exception as e:
        print(f"停止UI服务失败: {e}")
        if PID_FILE.exists():
            PID_FILE.unlink()

def restart_daemon(port=DEFAULT_PORT):
    """重启UI守护进程"""
    stop_daemon()
    time.sleep(1)
    start_daemon(port)

# 兼容性函数（与clp命令统一接口）
def start(port=DEFAULT_PORT):
    """start_daemon的别名"""
    return start_daemon(port)

def stop():
    """stop_daemon的别名"""
    return stop_daemon()

def restart(port=DEFAULT_PORT):
    """restart_daemon的别名"""
    return restart_daemon(port)
    print("重启UI服务...")
    stop_daemon()
    time.sleep(1)  # 等待完全停止
    start_daemon(port)
