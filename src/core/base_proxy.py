#!/usr/bin/env python3
"""
基础代理服务类 - 消除claude和codex的重复代码
提供统一的代理服务实现
"""
import asyncio
import base64
import json
import subprocess
import sys
import time
import uuid
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

        # 初始化路径
        self.config_dir = Path.home() / '.clp/run'
        self.config_dir.mkdir(parents=True, exist_ok=True)
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

                if response_truncated:
                    log_entry['response_truncated'] = True

                if total_response_bytes is not None:
                    log_entry['response_bytes'] = total_response_bytes

                # 限制日志文件为最多100条记录
                self._maintain_log_limit(log_entry)
            except Exception as exc:
                print(f"日志记录失败: {exc}")

        await asyncio.to_thread(_write_log)

    def _maintain_log_limit(self, new_log_entry: dict, max_logs: int = 100):
        """维护日志文件条数限制，只保留最近的max_logs条记录"""
        try:
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
                    'currentFailures': {},
                    'excludedConfigs': []
                },
                'codex': {
                    'failureThreshold': 3,
                    'currentFailures': {},
                    'excludedConfigs': []
                }
            }
        }

    def _ensure_lb_service_section(self, config: dict, service: str):
        """确保指定服务的负载均衡配置结构完整"""
        services = config.setdefault('services', {})
        service_section = services.setdefault(service, {})
        service_section.setdefault('failureThreshold', 3)
        service_section.setdefault('currentFailures', {})
        service_section.setdefault('excludedConfigs', [])

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

        service_section = self.lb_config.get('services', {}).get(self.service_name, {})
        threshold = service_section.get('failureThreshold', 3)
        failures = service_section.get('currentFailures', {})
        excluded = set(service_section.get('excludedConfigs', []))

        sorted_configs = sorted(
            configs.items(),
            key=lambda item: (-float(item[1].get('weight', 0) or 0), item[0])
        )

        for name, _ in sorted_configs:
            if failures.get(name, 0) >= threshold:
                continue
            if name in excluded:
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

        changed = False
        is_success = status_code is not None and 200 <= int(status_code) < 300

        if is_success:
            if failures.get(config_name, 0) != 0:
                failures[config_name] = 0
                changed = True
            if config_name in excluded:
                excluded.remove(config_name)
                changed = True
        else:
            new_count = failures.get(config_name, 0) + 1
            if failures.get(config_name) != new_count:
                failures[config_name] = new_count
                changed = True
            if new_count >= threshold and config_name not in excluded:
                excluded.append(config_name)
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
        excluded_headers = {'authorization', 'host', 'content-length'}
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

            # 构造返回头，移除跳跃性头信息
            excluded_response_headers = {'connection', 'transfer-encoding'}
            response_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in excluded_response_headers
            }

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

        # 通过环境变量控制代理服务监听地址
        proxy_host = os.getenv('CLP_PROXY_HOST', '0.0.0.0')

        try:
            with open(self.log_file, 'a') as log_file:
                uvicorn_cmd = [
                    sys.executable, '-m', 'uvicorn',
                    f'src.{self.service_name}.proxy:app',
                    '--host', proxy_host,
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
    
    def start(self) -> bool:
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
        
        import os
        project_root = Path(__file__).parent.parent.parent
        env = os.environ.copy()

        # 通过环境变量控制代理服务监听地址
        proxy_host = os.getenv('CLP_PROXY_HOST', '0.0.0.0')

        uvicorn_cmd = [
            sys.executable, '-m', 'uvicorn',
            f'{self.proxy_module_path}:app',
            '--host', proxy_host,
            '--port', str(self.port),
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
        self.pid_file.write_text(str(process.pid))

        # 等待服务启动
        time.sleep(1)

        if self.is_running():
            print(f"{self.service_name}服务启动成功 (端口: {self.port})")
            return True
        else:
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
    
    def restart(self) -> bool:
        """重启服务"""
        self.stop()
        time.sleep(1)
        return self.start()
    
    def status(self):
        """查看服务状态"""
        if self.is_running():
            pid = self.get_pid()
            active_config = self.config_manager.active_config
            print(f"{self.service_name}服务: 运行中 (PID: {pid}, 配置: {active_config})")
        else:
            print(f"{self.service_name}服务: 未运行")
