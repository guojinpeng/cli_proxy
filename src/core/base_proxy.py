#!/usr/bin/env python3
"""
基础代理服务类 - 消除claude和codex的重复代码
提供统一的代理服务实现
"""
import asyncio
import base64
import json
import os
import subprocess
import socket
import sys
import time
import uuid
from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse

from ..utils.usage_parser import (
    extract_usage_from_response,
    normalize_usage_record,
    empty_metrics,
    merge_usage_metrics,
)
from ..utils.platform_helper import create_detached_process
from .realtime_hub import RealTimeRequestHub

class BaseProxyService(ABC):
    """基础代理服务类"""
    
    def __init__(self, service_name: str, port: int, config_manager):
        """
        初始化代理服务

        Args:
            service_name: 服务名称 (claude/codex)
            port: 服务端口
            config_manager: 配置管理器实例
        """
        self.service_name = service_name
        self.port = port
        self.config_manager = config_manager

        # 初始化路径并收紧权限
        self.config_dir = Path.home() / '.clp/run'
        self._ensure_secure_directory(self.config_dir)
        self.pid_file = self.config_dir / f'{service_name}_proxy.pid'
        self.log_file = self.config_dir / f'{service_name}_proxy.log'

        # 数据目录
        self.data_dir = Path.home() / '.clp/data'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.traffic_log = self.data_dir / 'proxy_requests.jsonl'
        old_log = self.data_dir / 'traffic_statistics.jsonl'
        if not self.traffic_log.exists() and old_log.exists():
            try:
                old_log.rename(self.traffic_log)
            except OSError:
                # 如果重命名失败，则保留旧文件并继续使用旧路径
                self.traffic_log = old_log

        # 路由配置文件
        self.routing_config_file = self.data_dir / 'model_router_config.json'
        self.routing_config = self._load_routing_config()
        self.routing_config_signature = self._get_file_signature(self.routing_config_file)

        # 负载均衡配置文件
        self.lb_config_file = self.data_dir / 'lb_config.json'
        self.lb_config = self._load_lb_config()
        self.lb_config_signature = self._get_file_signature(self.lb_config_file)

        # 初始化异步HTTP客户端
        self.client = self._create_async_client()

        # 响应日志截断阈值（避免长流占用过多内存）
        self.max_logged_response_bytes = 1024 * 1024  # 1MB

        # 初始化实时事件中心
        self.realtime_hub = RealTimeRequestHub(service_name)

        # 初始化FastAPI应用
        self.app = FastAPI()
        self._setup_routes()
        self.app.add_event_handler("shutdown", self._shutdown_event)

        # 导入过滤器
        try:
            from ..filter.cached_request_filter import CachedRequestFilter
            self.request_filter = CachedRequestFilter()
        except ImportError:
            # 如果缓存版本不存在，使用原版本
            from ..filter.request_filter import filter_request_data
            self.filter_request_data = filter_request_data
            self.request_filter = None
    
    @staticmethod
    def _ensure_secure_directory(directory: Path):
        """确保目录存在并设置仅用户访问权限"""
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            # 在部分平台/文件系统上可能无法chmod，忽略
            pass
    
    def _create_async_client(self) -> httpx.AsyncClient:
        """创建并配置 httpx AsyncClient"""
        timeout = httpx.Timeout(  # 允许长时间流式响应
            timeout=None,
            connect=30.0,
            read=None,
            write=30.0,
            pool=None,
        )
        limits = httpx.Limits(
            max_connections=200,
            max_keepalive_connections=100,
        )
        return httpx.AsyncClient(timeout=timeout, limits=limits, headers={"Connection": "keep-alive"})

    async def _shutdown_event(self):
        """FastAPI 关闭事件，释放HTTP客户端资源"""
        await self.client.aclose()

    def _setup_routes(self):
        """设置API路由"""
        @self.app.api_route(
            "/{path:path}",
            methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        )
        async def proxy_route(path: str, request: Request):
            return await self.proxy(path, request)

        @self.app.websocket("/ws/realtime")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket实时事件端点"""
            await self.realtime_hub.connect(websocket)
            try:
                # 保持连接活跃，等待客户端消息或断开
                while True:
                    # 接收客户端的ping消息，保持连接
                    try:
                        await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                    except asyncio.TimeoutError:
                        # 发送ping消息保持连接
                        await websocket.send_text('{"type":"ping"}')
            except WebSocketDisconnect:
                pass
            except Exception as e:
                print(f"WebSocket连接异常: {e}")
            finally:
                self.realtime_hub.disconnect(websocket)

    async def log_request(
        self,
        method: str,
        path: str,
        status_code: int,
        duration_ms: int,
        target_headers: Optional[Dict] = None,
        filtered_body: Optional[bytes] = None,
        original_headers: Optional[Dict] = None,
        original_body: Optional[bytes] = None,
        response_content: Optional[bytes] = None,
        channel: Optional[str] = None,
        usage: Optional[Dict[str, Any]] = None,
        response_truncated: bool = False,
        total_response_bytes: Optional[int] = None,
        target_url: Optional[str] = None,
        response_headers: Optional[Dict] = None,
    ):
        """记录请求日志到jsonl文件（异步调度）"""

        def _write_log():
            try:
                log_entry = {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                    'service': self.service_name,
                    'method': method,
                    'path': target_url if target_url else path,
                    'status_code': status_code,
                    'duration_ms': duration_ms,
                    'target_headers': target_headers or {}
                }

                if channel:
                    log_entry['channel'] = channel

                if filtered_body:
                    log_entry['filtered_body'] = base64.b64encode(filtered_body).decode('utf-8')

                if original_headers:
                    log_entry['original_headers'] = original_headers

                if original_body:
                    log_entry['original_body'] = base64.b64encode(original_body).decode('utf-8')

                usage_record = usage
                if usage_record is None:
                    usage_record = extract_usage_from_response(self.service_name, response_content)
                usage_record = normalize_usage_record(self.service_name, usage_record)
                log_entry['usage'] = usage_record

                if response_content:
                    log_entry['response_content'] = base64.b64encode(response_content).decode('utf-8')

                if response_headers:
                    log_entry['response_headers'] = response_headers

                if response_truncated:
                    log_entry['response_truncated'] = True

                if total_response_bytes is not None:
                    log_entry['response_bytes'] = total_response_bytes

                # 限制日志文件为最多100条记录
                self._maintain_log_limit(log_entry)
            except Exception as exc:
                print(f"日志记录失败: {exc}")

        await asyncio.to_thread(_write_log)

    def _save_discarded_logs_usage(self, discarded_logs: list[dict]) -> None:
        """将被丢弃的日志的usage数据保存到历史记录"""
        if not discarded_logs:
            return

        try:
            # 聚合被丢弃日志的usage数据
            aggregated: Dict[str, Dict[str, Dict[str, int]]] = {}
            for entry in discarded_logs:
                usage = entry.get('usage', {})
                metrics = usage.get('metrics', {})
                if not metrics:
                    continue

                service = usage.get('service') or entry.get('service') or 'unknown'
                channel = entry.get('channel') or 'unknown'

                service_bucket = aggregated.setdefault(service, {})
                channel_bucket = service_bucket.setdefault(channel, empty_metrics())
                merge_usage_metrics(channel_bucket, metrics)

            if not aggregated:
                return

            # 加载现有历史记录
            history_file = self.data_dir / 'history_usage.json'
            history_usage: Dict[str, Dict[str, Dict[str, int]]] = {}

            if history_file.exists():
                try:
                    with open(history_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    # 规范化历史数据
                    for service, channels in (data or {}).items():
                        if not isinstance(channels, dict):
                            continue
                        service_bucket: Dict[str, Dict[str, int]] = {}
                        for channel, metrics in channels.items():
                            normalized = empty_metrics()
                            if isinstance(metrics, dict):
                                merge_usage_metrics(normalized, metrics)
                            service_bucket[channel] = normalized
                        history_usage[service] = service_bucket
                except (json.JSONDecodeError, OSError):
                    pass

            # 合并聚合的usage到历史记录
            for service, channels in aggregated.items():
                service_bucket = history_usage.setdefault(service, {})
                for channel, metrics in channels.items():
                    channel_bucket = service_bucket.setdefault(channel, empty_metrics())
                    merge_usage_metrics(channel_bucket, metrics)

            # 保存更新后的历史记录
            serializable = {
                service: {
                    channel: {key: int(value) for key, value in metrics.items()}
                    for channel, metrics in channels.items()
                }
                for service, channels in history_usage.items()
            }

            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(serializable, f, ensure_ascii=False, indent=2)

        except Exception as exc:
            print(f"保存被丢弃日志的usage失败: {exc}")

    def _maintain_log_limit(self, new_log_entry: dict):
        """维护日志文件条数限制，只保留最近的max_logs条记录"""
        try:
            # 从系统配置文件读取日志限制数量
            system_config_file = self.data_dir / 'system.json'
            max_logs = 50  # 默认值
            try:
                if system_config_file.exists():
                    with open(system_config_file, 'r', encoding='utf-8') as f:
                        system_config = json.load(f)
                        max_logs = system_config.get('logLimit', 50)
            except (json.JSONDecodeError, OSError) as e:
                print(f"读取系统配置失败，使用默认日志限制 {max_logs}: {e}")

            # 读取现有日志
            existing_logs = []
            if self.traffic_log.exists():
                with open(self.traffic_log, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                log_data = json.loads(line)
                                existing_logs.append(log_data)
                            except json.JSONDecodeError:
                                continue

            # 添加新日志条目
            existing_logs.append(new_log_entry)

            # 只保留最近的max_logs条记录
            if len(existing_logs) > max_logs:
                # 保存即将被丢弃的日志的usage数据到历史记录
                discarded_logs = existing_logs[:-max_logs]
                self._save_discarded_logs_usage(discarded_logs)

                existing_logs = existing_logs[-max_logs:]
            
            # 重写整个日志文件
            with open(self.traffic_log, 'w', encoding='utf-8') as f:
                for log_entry in existing_logs:
                    f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
                    
        except Exception as exc:
            print(f"维护日志文件限制失败: {exc}")
            # 如果维护失败，直接追加写入
            try:
                with open(self.traffic_log, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(new_log_entry, ensure_ascii=False) + '\n')
            except Exception as fallback_exc:
                print(f"备用日志写入也失败: {fallback_exc}")

    def _get_file_signature(self, file_path: Path) -> Tuple[int, int]:
        """获取文件签名，用于检测内容变化"""
        try:
            stat_result = file_path.stat()
            return stat_result.st_mtime_ns, stat_result.st_size
        except FileNotFoundError:
            return (0, 0)
        except OSError as exc:
            print(f"读取文件签名失败({file_path}): {exc}")
            return (0, 0)

    def _ensure_routing_config_current(self):
        """检查路由配置是否有更新，如有则重新加载"""
        current_signature = self._get_file_signature(self.routing_config_file)
        if current_signature != self.routing_config_signature:
            self.routing_config = self._load_routing_config()
            self.routing_config_signature = current_signature

    def _load_routing_config(self) -> dict:
        """加载路由配置"""
        try:
            if self.routing_config_file.exists():
                with open(self.routing_config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"加载路由配置失败: {e}")
        
        # 返回默认配置
        return {
            'mode': 'default',
            'modelMappings': {
                'claude': [],
                'codex': []
            },
            'configMappings': {
                'claude': [],
                'codex': []
            }
        }

    def _default_lb_config(self) -> dict:
        """构建负载均衡默认配置"""
        return {
            'mode': 'active-first',
            'services': {
                'claude': {
                    'failureThreshold': 3,
                    'autoResetMinutes': 10,
                    'currentFailures': {},
                    'excludedConfigs': [],
                    'excludedTimestamps': {},
                    'manualDisabledUntil': {}
                },
                'codex': {
                    'failureThreshold': 3,
                    'autoResetMinutes': 10,
                    'currentFailures': {},
                    'excludedConfigs': [],
                    'excludedTimestamps': {},
                    'manualDisabledUntil': {}
                }
            }
        }

    def _ensure_lb_service_section(self, config: dict, service: str):
        """确保指定服务的负载均衡配置结构完整"""
        services = config.setdefault('services', {})
        service_section = services.setdefault(service, {})
        threshold = service_section.get('failureThreshold', 3)
        try:
            threshold = int(threshold)
        except (TypeError, ValueError):
            threshold = 3
        if threshold <= 0:
            threshold = 3
        service_section['failureThreshold'] = threshold

        failures = service_section.get('currentFailures', {})
        if not isinstance(failures, dict):
            failures = {}
        normalized_failures = {}
        for key, value in failures.items():
            name = str(key)
            try:
                count = int(value)
            except (TypeError, ValueError):
                count = 0
            normalized_failures[name] = max(count, 0)
        service_section['currentFailures'] = normalized_failures

        excluded = service_section.get('excludedConfigs', [])
        if not isinstance(excluded, list):
            excluded = []
        service_section['excludedConfigs'] = [str(item) for item in excluded if isinstance(item, str)]

        auto_reset = service_section.get('autoResetMinutes', 10)
        try:
            auto_reset = int(auto_reset)
        except (TypeError, ValueError):
            auto_reset = 10
        if auto_reset < 0:
            auto_reset = 0
        service_section['autoResetMinutes'] = auto_reset

        timestamps = service_section.get('excludedTimestamps', {})
        if not isinstance(timestamps, dict):
            timestamps = {}
        normalized_timestamps = {}
        for key, value in timestamps.items():
            name = str(key)
            try:
                ts_value = float(value)
            except (TypeError, ValueError):
                continue
            if ts_value > 0:
                normalized_timestamps[name] = ts_value
        service_section['excludedTimestamps'] = normalized_timestamps

        manual_disabled = service_section.get('manualDisabledUntil', {})
        if not isinstance(manual_disabled, dict):
            manual_disabled = {}
        normalized_manual = {}
        for key, value in manual_disabled.items():
            name = str(key)
            try:
                date_str = str(value).strip()
            except Exception:
                continue
            if date_str:
                normalized_manual[name] = date_str
        service_section['manualDisabledUntil'] = normalized_manual

    def _apply_lb_auto_reset(self, service_section: dict) -> bool:
        """根据配置自动重置已跳过的目标"""
        interval_minutes = service_section.get('autoResetMinutes', 0)
        try:
            interval_minutes = int(interval_minutes)
        except (TypeError, ValueError):
            interval_minutes = 0

        if interval_minutes <= 0:
            return False

        excluded = service_section.get('excludedConfigs', [])
        if not excluded:
            return False

        timestamps = service_section.setdefault('excludedTimestamps', {})
        failures = service_section.setdefault('currentFailures', {})
        now = time.time()
        changed = False
        expired = []

        for name in list(excluded):
            ts_value = timestamps.get(name)
            if not isinstance(ts_value, (int, float)):
                expired.append(name)
                continue
            if now - float(ts_value) >= interval_minutes * 60:
                expired.append(name)

        for name in expired:
            if name in excluded:
                excluded.remove(name)
            timestamps.pop(name, None)
            if name in failures and failures[name] != 0:
                failures[name] = 0
            changed = True

        return changed

    def _cleanup_manual_disabled(self, service_section: dict) -> bool:
        """清理已过期的手动禁用项"""
        manual_disabled = service_section.setdefault('manualDisabledUntil', {})
        if not isinstance(manual_disabled, dict):
            service_section['manualDisabledUntil'] = {}
            return True

        today = datetime.now().date().isoformat()
        changed = False

        for name in list(manual_disabled.keys()):
            value = manual_disabled.get(name)
            if not isinstance(value, str):
                manual_disabled.pop(name, None)
                changed = True
                continue
            date_str = value.strip()
            if not date_str or date_str != today:
                manual_disabled.pop(name, None)
                changed = True

        return changed

    def _load_lb_config(self) -> dict:
        """加载负载均衡配置"""
        try:
            if self.lb_config_file.exists():
                with open(self.lb_config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                data = self._default_lb_config()
        except Exception as exc:
            print(f"加载负载均衡配置失败: {exc}")
            data = self._default_lb_config()

        if 'mode' not in data:
            data['mode'] = 'active-first'

        self._ensure_lb_service_section(data, 'claude')
        self._ensure_lb_service_section(data, 'codex')
        return data

    def _ensure_lb_config_current(self):
        """检查负载均衡配置是否有更新"""
        current_signature = self._get_file_signature(self.lb_config_file)
        if current_signature != self.lb_config_signature:
            self.lb_config = self._load_lb_config()
            self.lb_config_signature = current_signature

    def _persist_lb_config(self):
        """持久化负载均衡配置"""
        try:
            with open(self.lb_config_file, 'w', encoding='utf-8') as f:
                json.dump(self.lb_config, f, ensure_ascii=False, indent=2)
            self.lb_config_signature = self._get_file_signature(self.lb_config_file)
        except OSError as exc:
            print(f"保存负载均衡配置失败: {exc}")

    def reload_lb_config(self):
        """重新加载负载均衡配置"""
        self.lb_config = self._load_lb_config()
        self.lb_config_signature = self._get_file_signature(self.lb_config_file)

    def _apply_model_routing(self, body: bytes) -> Tuple[bytes, Optional[str]]:
        """应用模型路由规则，返回修改后的body和要使用的配置名"""
        routing_mode = self.routing_config.get('mode', 'default')
        
        if routing_mode == 'default':
            return body, None
        
        try:
            # 解析请求体
            if not body:
                return body, None
                
            body_str = body.decode('utf-8')
            body_json = json.loads(body_str)
            
            # 获取模型名称
            model = body_json.get('model')
            if not model:
                return body, None
            
            if routing_mode == 'model-mapping':
                return self._apply_model_mapping(body_json, model, body)
            elif routing_mode == 'config-mapping':
                return self._apply_config_mapping(body_json, model, body)
                
        except Exception as e:
            print(f"应用模型路由失败: {e}")
            
        return body, None

    def _apply_model_mapping(self, body_json: dict, model: str, original_body: bytes) -> Tuple[bytes, Optional[str]]:
        """应用模型→模型映射和配置→模型映射"""
        mappings = self.routing_config.get('modelMappings', {}).get(self.service_name, [])

        for mapping in mappings:
            source = mapping.get('source', '').strip()
            target = mapping.get('target', '').strip()
            source_type = mapping.get('source_type', 'model').strip()

            if not source or not target:
                continue

            if source_type == 'config':
                # 配置→模型映射
                current_config = self._get_current_active_config()
                if current_config == source:
                    body_json['model'] = target
                    modified_body = json.dumps(body_json, ensure_ascii=False).encode('utf-8')
                    print(f"配置映射: {source} -> {target}")
                    return modified_body, None
            elif source_type == 'model':
                # 模型→模型映射
                if model == source:
                    body_json['model'] = target
                    modified_body = json.dumps(body_json, ensure_ascii=False).encode('utf-8')
                    print(f"模型映射: {source} -> {target}")
                    return modified_body, None

        return original_body, None

    def _apply_config_mapping(self, body_json: dict, model: str, original_body: bytes) -> Tuple[bytes, Optional[str]]:
        """应用模型→配置映射"""
        mappings = self.routing_config.get('configMappings', {}).get(self.service_name, [])
        
        for mapping in mappings:
            mapped_model = mapping.get('model', '').strip()
            target_config = mapping.get('config', '').strip()
            
            if mapped_model and target_config and model == mapped_model:
                # 检查目标配置是否存在
                if target_config in self.config_manager.configs:
                    print(f"配置映射: {model} -> {target_config}")
                    return original_body, target_config
                else:
                    print(f"配置映射失败: 配置 {target_config} 不存在")
        
        return original_body, None

    def _get_current_active_config(self) -> Optional[str]:
        """获取当前激活的配置名（考虑负载均衡）"""
        configs = self.config_manager.configs
        return self._select_config_by_loadbalance(configs)

    def _select_config_by_loadbalance(self, configs: Dict[str, Dict[str, Any]]) -> Optional[str]:
        """根据负载均衡策略选择配置名"""
        self._ensure_lb_config_current()
        mode = self.lb_config.get('mode', 'active-first')
        if mode == 'weight-based':
            selected = self._select_weighted_config(configs)
            if selected:
                return selected
        return self.config_manager.active_config

    def _select_weighted_config(self, configs: Dict[str, Dict[str, Any]]) -> Optional[str]:
        """按权重选择配置"""
        if not configs:
            return None

        self._ensure_lb_service_section(self.lb_config, self.service_name)
        service_section = self.lb_config['services'][self.service_name]
        changed = False
        if self._apply_lb_auto_reset(service_section):
            changed = True
        if self._cleanup_manual_disabled(service_section):
            changed = True
        if changed:
            self._persist_lb_config()

        threshold = service_section.get('failureThreshold', 3)
        failures = service_section.get('currentFailures', {})
        excluded = set(service_section.get('excludedConfigs', []))
        manual_disabled = service_section.get('manualDisabledUntil', {})
        today_key = datetime.now().date().isoformat()

        sorted_configs = sorted(
            configs.items(),
            key=lambda item: (-float(item[1].get('weight', 0) or 0), item[0])
        )

        for name, _ in sorted_configs:
            if failures.get(name, 0) >= threshold:
                continue
            if name in excluded:
                continue
            if isinstance(manual_disabled, dict) and manual_disabled.get(name) == today_key:
                continue
            return name

        active_config = self.config_manager.active_config
        if active_config in configs:
            return active_config
        return sorted_configs[0][0] if sorted_configs else None

    def reload_routing_config(self):
        """重新加载路由配置"""
        self.routing_config = self._load_routing_config()
        self.routing_config_signature = self._get_file_signature(self.routing_config_file)

    def _record_lb_result(self, config_name: Optional[str], status_code: int):
        """记录请求结果以更新负载均衡状态"""
        if not config_name:
            return

        self._ensure_lb_config_current()
        if self.lb_config.get('mode', 'active-first') != 'weight-based':
            return

        self._ensure_lb_service_section(self.lb_config, self.service_name)
        service_section = self.lb_config['services'][self.service_name]
        threshold = service_section.get('failureThreshold', 3)
        failures = service_section.setdefault('currentFailures', {})
        excluded = service_section.setdefault('excludedConfigs', [])
        timestamps = service_section.setdefault('excludedTimestamps', {})
        manual_disabled = service_section.setdefault('manualDisabledUntil', {})

        changed = False
        if self._apply_lb_auto_reset(service_section):
            changed = True
        if self._cleanup_manual_disabled(service_section):
            changed = True
        is_success = status_code is not None and 200 <= int(status_code) < 300

        if is_success:
            if failures.get(config_name, 0) != 0:
                failures[config_name] = 0
                changed = True
            if config_name in excluded:
                excluded.remove(config_name)
                changed = True
            if timestamps.pop(config_name, None) is not None:
                changed = True
        else:
            new_count = failures.get(config_name, 0) + 1
            if failures.get(config_name) != new_count:
                failures[config_name] = new_count
                changed = True
            if new_count >= threshold and config_name not in excluded:
                excluded.append(config_name)
                timestamps[config_name] = time.time()
                changed = True
            elif new_count >= threshold:
                # 已经处于排除列表中，刷新排除时间戳
                timestamps[config_name] = time.time()
            else:
                if config_name in timestamps:
                    timestamps.pop(config_name, None)
                    changed = True

        if changed:
            self._persist_lb_config()

    def build_target_param(self, path: str, request: Request, body: bytes) -> Tuple[str, Dict, bytes, Optional[str]]:
        """
        构建请求参数

        Returns:
            (target_url, headers, body, active_config_name)
        """
        # 使用最新的路由配置
        self._ensure_routing_config_current()

        # 应用模型路由规则
        modified_body, config_override = self._apply_model_routing(body)

        # 预加载配置列表，减少重复 I/O
        configs = self.config_manager.configs

        # 确定要使用的配置
        if config_override:
            active_config_name = config_override
        else:
            active_config_name = self._select_config_by_loadbalance(configs)

        config_data = configs.get(active_config_name)
        if not config_data and active_config_name:
            # 配置字典可能因缓存过期，需要重新获取
            configs = self.config_manager.configs
            config_data = configs.get(active_config_name)

        if not config_data:
            fallback_name = self.config_manager.active_config
            configs = self.config_manager.configs
            config_data = configs.get(fallback_name)
            active_config_name = fallback_name

        if not config_data:
            raise ValueError(f"未找到激活配置: {active_config_name}")
        
        # 构建目标URL
        base_url = config_data['base_url'].rstrip('/')
        normalized_path = path.lstrip('/')
        target_url = f"{base_url}/{normalized_path}" if normalized_path else base_url

        raw_query = request.url.query
        if raw_query:
            target_url = f"{target_url}?{raw_query}"

        # 处理headers，排除会被重新设置的头
        excluded_headers = {'x-api-key', 'authorization', 'host', 'content-length'}
        headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
        headers['host'] = urlsplit(target_url).netloc
        headers.setdefault('connection', 'keep-alive')
        if config_data.get('api_key'):
            headers['x-api-key'] = config_data['api_key']
        if config_data.get('auth_token'):
            headers['authorization'] = f'Bearer {config_data["auth_token"]}'

        return target_url, headers, modified_body, active_config_name

    @abstractmethod
    def test_endpoint(self, model: str, base_url: str, auth_token: str = None, api_key: str = None, extra_params: dict = None) -> dict:
        """
        测试API端点连通性

        Args:
            model: 模型名称
            base_url: 目标API地址
            auth_token: 认证令牌（可选）
            api_key: API密钥（可选）
            extra_params: 扩展参数（可选）

        Returns:
            dict: 包含测试结果的字典
        """
        pass

    def apply_request_filter(self, data: bytes) -> bytes:
        """应用请求过滤器"""
        if self.request_filter:
            # 使用缓存版本的过滤器
            return self.request_filter.apply_filters(data)
        else:
            # 使用原版本的过滤器
            return self.filter_request_data(data)
    
    async def proxy(self, path: str, request: Request):
        """处理代理请求"""
        start_time = time.time()
        request_id = str(uuid.uuid4())

        original_headers = {k: v for k, v in request.headers.items()}
        original_body = await request.body()

        active_config_name: Optional[str] = None
        target_headers: Optional[Dict[str, str]] = None
        filtered_body: Optional[bytes] = None
        target_url: Optional[str] = None

        try:
            target_url, target_headers, target_body, active_config_name = self.build_target_param(path, request, original_body)

            # 发送请求开始事件
            await self.realtime_hub.request_started(
                request_id=request_id,
                method=request.method,
                path=path,
                channel=active_config_name or "unknown",
                headers=target_headers,
                target_url=target_url
            )

        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

        # 应用请求过滤器，放到线程池避免阻塞事件循环
        filtered_body = await asyncio.to_thread(self.apply_request_filter, target_body)

        # 检测是否需要流式传输
        headers_lower = {k.lower(): v for k, v in original_headers.items()}
        x_stainless_helper_method = headers_lower.get('x-stainless-helper-method', '').lower()
        content_type = headers_lower.get('content-type', '').lower()
        accept = headers_lower.get('accept', '').lower()
        is_stream = (
            'text/event-stream' in accept or
            'text/event-stream' in content_type or
            'stream' in content_type or
            'application/x-ndjson' in content_type or
            "stream" in x_stainless_helper_method
        )

        try:
            request_out = self.client.build_request(
                method=request.method,
                url=target_url,
                headers=target_headers,
                content=filtered_body if filtered_body else None,
            )
            response = await self.client.send(request_out, stream=is_stream)

            status_code = response.status_code
            lb_result_recorded = False

            if not (200 <= status_code < 300):
                await asyncio.to_thread(self._record_lb_result, active_config_name, status_code)
                lb_result_recorded = True

            # 构造返回头，标记被剔除的头信息
            excluded_response_headers = {}
            response_headers = {}  # 用于实际返回
            response_headers_for_log = {}  # 用于日志记录（包含标记）

            for k, v in response.headers.items():
                k_lower = k.lower()
                if k_lower in excluded_response_headers:
                    # 用于日志：保留但标记已剔除
                    response_headers_for_log[f"{k}[已剔除]"] = v
                else:
                    # 用于返回和日志
                    response_headers[k] = v
                    response_headers_for_log[k] = v

            collected = bytearray()
            total_response_bytes = 0
            response_truncated = False
            first_chunk = True

            async def iterator():
                nonlocal response_truncated, total_response_bytes, first_chunk, lb_result_recorded
                try:
                    async for chunk in response.aiter_bytes():
                        if not chunk:
                            continue

                        current_duration = int((time.time() - start_time) * 1000)

                        # 首次接收数据时标记为流式状态
                        if first_chunk:
                            await self.realtime_hub.request_streaming(request_id, current_duration)
                            first_chunk = False

                        # 尝试解码为文本发送实时更新
                        try:
                            chunk_text = chunk.decode('utf-8', errors='ignore')
                            if chunk_text.strip():  # 只发送非空chunk
                                await self.realtime_hub.response_chunk(
                                    request_id, chunk_text, current_duration
                                )
                        except Exception:
                            pass  # 忽略解码失败

                        total_response_bytes += len(chunk)
                        if len(collected) < self.max_logged_response_bytes:
                            remaining = self.max_logged_response_bytes - len(collected)
                            collected.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                response_truncated = True
                        else:
                            response_truncated = True
                        yield chunk
                finally:
                    final_duration = int((time.time() - start_time) * 1000)

                    # 发送请求完成事件
                    await self.realtime_hub.request_completed(
                        request_id=request_id,
                        status_code=status_code,
                        duration_ms=final_duration,
                        success=200 <= status_code < 400
                    )

                    await response.aclose()

                    # 原有日志记录逻辑
                    response_content = bytes(collected) if collected else None
                    await self.log_request(
                        method=request.method,
                        path=path,
                        status_code=status_code,
                        duration_ms=final_duration,
                        target_headers=target_headers,
                        filtered_body=filtered_body,
                        original_headers=original_headers,
                        original_body=original_body,
                        response_content=response_content,
                        channel=active_config_name,
                        response_truncated=response_truncated,
                        total_response_bytes=total_response_bytes,
                        target_url=target_url,
                        response_headers=response_headers_for_log,
                    )

                    if not lb_result_recorded:
                        await asyncio.to_thread(self._record_lb_result, active_config_name, status_code)
                        lb_result_recorded = True

            return StreamingResponse(
                iterator(),
                status_code=status_code,
                headers=response_headers
            )
        except httpx.RequestError as exc:
            duration_ms = int((time.time() - start_time) * 1000)

            if isinstance(exc, httpx.ConnectTimeout):
                error_msg = "连接超时"
            elif isinstance(exc, httpx.ReadTimeout):
                error_msg = "响应读取超时"
            elif isinstance(exc, httpx.ConnectError):
                error_msg = "连接错误"
            elif isinstance(exc, httpx.HTTPStatusError):
                error_msg = "上游返回错误状态"
            else:
                error_msg = "请求失败"

            response_data = {"error": error_msg, "detail": str(exc)}
            status_code = 500

            # 发送错误事件
            await self.realtime_hub.request_completed(
                request_id=request_id,
                status_code=status_code,
                duration_ms=duration_ms,
                success=False
            )

            await self.log_request(
                method=request.method,
                path=path,
                status_code=status_code,
                duration_ms=duration_ms,
                target_headers=target_headers,
                filtered_body=filtered_body,
                original_headers=original_headers,
                original_body=original_body,
                channel=active_config_name,
                target_url=target_url
            )

            await asyncio.to_thread(self._record_lb_result, active_config_name, status_code)

            return JSONResponse(response_data, status_code=status_code)

    def run_app(self):
        """启动代理服务"""
        import os
        # 切换到项目根目录
        project_root = Path(__file__).parent.parent.parent
        
        # 在daemon环境中，需要明确指定环境和重定向
        env = os.environ.copy()
        
        try:
            with open(self.log_file, 'a') as log_file:
                uvicorn_cmd = [
                    sys.executable, '-m', 'uvicorn',
                    f'src.{self.service_name}.proxy:app',
                    '--host', '0.0.0.0',
                    '--port', str(self.port),
                    '--http', 'h11',
                    '--timeout-keep-alive', '60',
                    '--limit-concurrency', '500',
                ]
                subprocess.run(
                    uvicorn_cmd,
                    cwd=str(project_root),
                    env=env,
                    stdout=log_file,
                    stderr=log_file,
                    stdin=subprocess.DEVNULL
                )
                print(f"启动{self.service_name}代理成功 在端口 {self.port}")
        except Exception as e:
            print(f"启动{self.service_name}代理失败: {e}")


class BaseServiceController(ABC):
    """基础服务控制器类"""
    
    def __init__(self, service_name: str, port: int, config_manager, proxy_module_path: str):
        """
        初始化服务控制器
        
        Args:
            service_name: 服务名称
            port: 服务端口
            config_manager: 配置管理器实例
            proxy_module_path: 代理模块路径 (如 'src.claude.proxy')
        """
        self.service_name = service_name
        self.port = port
        self.config_manager = config_manager
        self.proxy_module_path = proxy_module_path
        
        # 初始化路径
        self.config_dir = Path.home() / '.clp/run'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.pid_file = self.config_dir / f'{service_name}_proxy.pid'
        self.log_file = self.config_dir / f'{service_name}_proxy.log'
    
    @staticmethod
    def _ensure_secure_directory(directory: Path):
        """确保运行目录存在且权限安全"""
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            # 在部分平台可能不支持 chmod，忽略即可
            pass

    def _write_pid_file(self, pid: int):
        """以受限权限写入 PID 文件"""
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.pid_file, flags, 0o600)
        with os.fdopen(fd, 'w') as pid_handle:
            pid_handle.write(str(pid))

    @staticmethod
    def _is_port_open(port: int, host: str = '127.0.0.1') -> bool:
        """检查端口是否可用"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                return sock.connect_ex((host, port)) == 0
            except OSError:
                return False

    def _wait_for_service_ready(self, port: int, timeout: float = 10.0, interval: float = 0.2) -> bool:
        """轮询等待服务就绪。若进程不在运行，立即失败；若在运行则等待端口就绪。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.is_running():
                return False
            if self._is_port_open(port):
                return True
            time.sleep(interval)
        return self.is_running() and self._is_port_open(port)
    
    def get_pid(self) -> Optional[int]:
        """获取服务进程PID"""
        if self.pid_file.exists():
            try:
                return int(self.pid_file.read_text().strip())
            except:
                return None
        return None
    
    def is_running(self) -> bool:
        """检查服务是否在运行"""
        import psutil
        pid = self.get_pid()
        if pid:
            try:
                process = psutil.Process(pid)
                return process.is_running()
            except psutil.NoSuchProcess:
                return False
        return False
    
    def start(self, port: Optional[int] = None) -> bool:
        """启动服务"""
        if self.is_running():
            print(f"{self.service_name}服务已经在运行")
            return False
        
        config_file_path = None
        ensure_file_fn = getattr(self.config_manager, 'ensure_config_file', None)
        if callable(ensure_file_fn):
            config_file_path = ensure_file_fn()
        elif hasattr(self.config_manager, 'config_file'):
            config_file_path = getattr(self.config_manager, 'config_file')

        # 检查配置
        configs = self.config_manager.configs
        if not configs:
            if config_file_path:
                print(f"警告: {self.service_name}配置为空，将以占位模式启动。请编辑 {config_file_path} 补充配置后重启。")
            else:
                print(f"警告: 未检测到{self.service_name}配置文件，将以占位模式启动。")
        
        project_root = Path(__file__).parent.parent.parent
        env = os.environ.copy()
        original_port = self.port
        target_port = port if port is not None else self.port
        
        uvicorn_cmd = [
            sys.executable, '-m', 'uvicorn',
            f'{self.proxy_module_path}:app',
            '--host', '0.0.0.0',
            '--port', str(target_port),
            '--http', 'h11',
            '--timeout-keep-alive', '60',
            '--limit-concurrency', '500',
        ]
        with open(self.log_file, 'a') as log_handle:
            # 在独立进程组中运行，避免控制台信号终止子进程
            process = create_detached_process(
                uvicorn_cmd,
                log_handle,
                cwd=str(project_root),
                env=env,
            )

        # 保存PID
        self._write_pid_file(process.pid)

        if self._wait_for_service_ready(target_port):
            self.port = target_port
            print(f"{self.service_name}服务启动成功 (端口: {self.port})")
            return True

        # 启动失败，恢复端口并清理 PID 文件
        self.port = original_port
        if self.pid_file.exists():
            self.pid_file.unlink()
        print(f"{self.service_name}服务启动失败")
        return False
    
    def stop(self) -> bool:
        """停止服务"""
        import psutil
        
        if not self.is_running():
            print(f"{self.service_name}服务未运行")
            return False
        
        pid = self.get_pid()
        if pid:
            try:
                process = psutil.Process(pid)
                process.terminate()
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
            except psutil.NoSuchProcess:
                pass
            
            # 清理PID文件
            if self.pid_file.exists():
                self.pid_file.unlink()
            
            print(f"{self.service_name}服务已停止")
            return True
        
        return False
    
    def restart(self, port: Optional[int] = None) -> bool:
        """重启服务"""
        self.stop()
        time.sleep(1)
        return self.start(port=port)
    
    def status(self) -> Dict[str, Any]:
        """返回服务状态信息"""
        running = self.is_running()
        pid = self.get_pid() if running else None
        active_config = self.config_manager.active_config
        return {
            'service': self.service_name,
            'running': running,
            'pid': pid,
            'active_config': active_config,
            'port': self.port,
        }
