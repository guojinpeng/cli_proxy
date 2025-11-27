import copy
import json
import time
from pathlib import Path
from threading import Event, RLock, Thread
from typing import Any, Dict, Optional, Tuple

from flask import Flask, jsonify, request, send_file

from src.utils.usage_parser import (
    METRIC_KEYS,
    empty_metrics,
    format_usage_value,
    merge_usage_metrics,
    normalize_usage_record,
)

# 数据目录 - 使用绝对路径
DATA_DIR = Path.home() / '.clp/data'
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR = Path(__file__).resolve().parent / 'static'

LOG_FILE = DATA_DIR / 'proxy_requests.jsonl'
OLD_LOG_FILE = DATA_DIR / 'traffic_statistics.jsonl'
HISTORY_FILE = DATA_DIR / 'history_usage.json'
SYSTEM_CONFIG_FILE = DATA_DIR / 'system.json'

if OLD_LOG_FILE.exists() and not LOG_FILE.exists():
    try:
        OLD_LOG_FILE.rename(LOG_FILE)
    except OSError:
        pass

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path='/static')


def _resolve_log_path() -> Optional[Path]:
    if LOG_FILE.exists():
        return LOG_FILE
    if OLD_LOG_FILE.exists():
        return OLD_LOG_FILE
    return None


def _get_file_signature(path: Optional[Path]) -> Tuple[int, int]:
    if path is None:
        return (0, 0)
    try:
        stat_result = path.stat()
        return stat_result.st_mtime_ns, stat_result.st_size
    except (FileNotFoundError, OSError):
        return (0, 0)


_LOGS_CACHE_LOCK = RLock()
_LOGS_CACHE: Dict[str, Any] = {
    'path': None,
    'signature': (0, 0),
    'logs': [],
}

_HISTORY_CACHE_LOCK = RLock()
_HISTORY_CACHE: Dict[str, Any] = {
    'signature': (0, 0),
    'history': {},
}

_USAGE_SNAPSHOT_CACHE_LOCK = RLock()
_USAGE_SNAPSHOT_CACHE: Dict[str, Any] = {
    'log_key': (None, (0, 0)),
    'history_signature': (0, 0),
    'data': None,
}

_USAGE_SUMMARY_CACHE_LOCK = RLock()
_USAGE_SUMMARY_CACHE: Dict[str, Any] = {
    'log_key': (None, (0, 0)),
    'history_signature': (0, 0),
    'summary': None,
    'request_count': 0,
    'timestamp': None,
}
_USAGE_SUMMARY_READY = Event()
_USAGE_REFRESH_EVENT = Event()
_USAGE_REFRESH_THREAD: Optional[Thread] = None


def _build_usage_summary_payload(
    combined_usage: Dict[str, Dict[str, Dict[str, int]]]
) -> Dict[str, Any]:
    service_usage_totals: Dict[str, Dict[str, int]] = {}
    for service_name, channels in combined_usage.items():
        service_usage_totals[service_name] = compute_total_metrics(channels)

    for expected_service in ('claude', 'codex'):
        service_usage_totals.setdefault(expected_service, empty_metrics())

    overall_totals = empty_metrics()
    for totals in service_usage_totals.values():
        merge_usage_metrics(overall_totals, totals)

    return {
        'totals': overall_totals,
        'formatted_totals': format_metrics(overall_totals),
        'per_service': {
            service: {
                'metrics': totals,
                'formatted': format_metrics(totals)
            }
            for service, totals in service_usage_totals.items()
        }
    }


def _refresh_usage_summary(force: bool = False) -> None:
    log_path = _resolve_log_path()
    log_key = (str(log_path.resolve()), _get_file_signature(log_path)) if log_path else (None, (0, 0))
    history_signature = _get_file_signature(HISTORY_FILE if HISTORY_FILE.exists() else None)

    with _USAGE_SUMMARY_CACHE_LOCK:
        cache_key = _USAGE_SUMMARY_CACHE['log_key']
        cache_history = _USAGE_SUMMARY_CACHE['history_signature']
        cache_summary = _USAGE_SUMMARY_CACHE['summary']
        if not force and cache_summary is not None and cache_key == log_key and cache_history == history_signature:
            _USAGE_SUMMARY_READY.set()
            return
        _USAGE_SUMMARY_READY.clear()

    logs = load_logs()
    history_usage = load_history_usage()
    current_usage = aggregate_usage_from_logs(logs)
    combined_usage = combine_usage_maps(current_usage, history_usage)
    summary_payload = _build_usage_summary_payload(combined_usage)
    request_count = len(logs)
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')

    with _USAGE_SUMMARY_CACHE_LOCK:
        _USAGE_SUMMARY_CACHE['log_key'] = log_key
        _USAGE_SUMMARY_CACHE['history_signature'] = history_signature
        _USAGE_SUMMARY_CACHE['summary'] = summary_payload
        _USAGE_SUMMARY_CACHE['request_count'] = request_count
        _USAGE_SUMMARY_CACHE['timestamp'] = timestamp
        _USAGE_SUMMARY_READY.set()


def _usage_summary_worker():
    while True:
        triggered = _USAGE_REFRESH_EVENT.wait(timeout=5.0)
        _USAGE_REFRESH_EVENT.clear()
        try:
            _refresh_usage_summary(force=triggered)
        except Exception as exc:
            print(f"Usage summary refresh failed: {exc}")
            _USAGE_SUMMARY_READY.set()


def _ensure_usage_summary_worker_started():
    global _USAGE_REFRESH_THREAD
    if _USAGE_REFRESH_THREAD is not None:
        return
    _USAGE_REFRESH_THREAD = Thread(target=_usage_summary_worker, name='usage-summary-worker', daemon=True)
    _USAGE_REFRESH_THREAD.start()
    _USAGE_REFRESH_EVENT.set()


def _trigger_usage_summary_refresh(async_mode: bool = False) -> None:
    _ensure_usage_summary_worker_started()
    if async_mode:
        _USAGE_REFRESH_EVENT.set()
    else:
        _refresh_usage_summary(force=True)


_ensure_usage_summary_worker_started()


def _get_cached_usage_summary(timeout: float = 0.5) -> Tuple[Optional[Dict[str, Any]], int, Optional[str]]:
    _ensure_usage_summary_worker_started()
    _USAGE_SUMMARY_READY.wait(timeout=timeout)
    with _USAGE_SUMMARY_CACHE_LOCK:
        summary = _USAGE_SUMMARY_CACHE['summary']
        request_count = _USAGE_SUMMARY_CACHE['request_count']
        timestamp = _USAGE_SUMMARY_CACHE['timestamp']

    summary_copy = copy.deepcopy(summary) if summary is not None else None
    return summary_copy, int(request_count or 0), timestamp


def _safe_json_load(line: str) -> Dict[str, Any]:
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {}


def _config_signature(config_entry: Dict[str, Any]) -> tuple:
    """Create a comparable signature for a config entry to help detect renames."""
    if not isinstance(config_entry, dict):
        return tuple()
    return (
        config_entry.get('base_url'),
        config_entry.get('auth_token'),
        config_entry.get('api_key'),
    )


def _detect_config_renames(old_configs: Dict[str, Any], new_configs: Dict[str, Any]) -> Dict[str, str]:
    """Return mapping of {old_name: new_name} for configs that only changed key names."""
    rename_map: Dict[str, str] = {}
    if not isinstance(old_configs, dict) or not isinstance(new_configs, dict):
        return rename_map

    old_signatures: Dict[tuple, list[str]] = {}
    for name, cfg in old_configs.items():
        sig = _config_signature(cfg)
        old_signatures.setdefault(sig, []).append(name)

    new_signatures: Dict[tuple, list[str]] = {}
    for name, cfg in new_configs.items():
        sig = _config_signature(cfg)
        new_signatures.setdefault(sig, []).append(name)

    for signature, old_names in old_signatures.items():
        new_names = new_signatures.get(signature)
        if not new_names:
            continue
        if set(old_names) == set(new_names):
            continue
        if len(old_names) == len(new_names) == 1:
            old_name = old_names[0]
            new_name = new_names[0]
            if old_name != new_name:
                rename_map[old_name] = new_name

    return rename_map


def _rename_history_channels(service: str, rename_map: Dict[str, str]) -> None:
    if not rename_map:
        return
    history_usage = load_history_usage()
    service_bucket = history_usage.get(service)
    if not service_bucket:
        return

    changed = False
    for old_name, new_name in rename_map.items():
        if old_name == new_name:
            continue
        if old_name not in service_bucket:
            continue

        existing_metrics = service_bucket.pop(old_name)
        target_metrics = service_bucket.get(new_name)
        if target_metrics:
            merge_usage_metrics(target_metrics, existing_metrics)
        else:
            service_bucket[new_name] = existing_metrics
        changed = True

    if changed:
        save_history_usage(history_usage)


def _rename_log_channels(service: str, rename_map: Dict[str, str]) -> None:
    if not rename_map or not LOG_FILE.exists():
        return

    temp_path = LOG_FILE.with_suffix('.tmp')
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as src, open(temp_path, 'w', encoding='utf-8') as dst:
            for raw_line in src:
                if not raw_line.strip():
                    dst.write(raw_line)
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError:
                    dst.write(raw_line)
                    continue

                if record.get('service') == service:
                    channel_name = record.get('channel')
                    if channel_name in rename_map:
                        record['channel'] = rename_map[channel_name]
                        raw_line = json.dumps(record, ensure_ascii=False) + '\n'
                dst.write(raw_line)
    except Exception:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise

    temp_path.replace(LOG_FILE)
    _trigger_usage_summary_refresh(async_mode=True)


def _sync_router_config_names(service: str, rename_map: Dict[str, str]) -> None:
    """同步模型路由配置中的配置名称"""
    if not rename_map:
        return

    router_config_file = DATA_DIR / 'model_router_config.json'
    if not router_config_file.exists():
        return

    try:
        with open(router_config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        changed = False

        # 更新 modelMappings 中的配置名称
        if 'modelMappings' in config and service in config['modelMappings']:
            for mapping in config['modelMappings'][service]:
                if mapping.get('source_type') == 'config' and mapping.get('source') in rename_map:
                    old_name = mapping['source']
                    new_name = rename_map[old_name]
                    mapping['source'] = new_name
                    changed = True

        # 更新 configMappings 中的配置名称
        if 'configMappings' in config and service in config['configMappings']:
            for mapping in config['configMappings'][service]:
                if mapping.get('config') in rename_map:
                    old_name = mapping['config']
                    new_name = rename_map[old_name]
                    mapping['config'] = new_name
                    changed = True

        if changed:
            with open(router_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"同步路由配置名称失败: {e}")


def _sync_loadbalance_config_names(service: str, rename_map: Dict[str, str]) -> None:
    """同步负载均衡配置中的配置名称"""
    if not rename_map:
        return

    lb_config_file = DATA_DIR / 'lb_config.json'
    if not lb_config_file.exists():
        return

    try:
        with open(lb_config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        changed = False
        service_config = config.get('services', {}).get(service, {})

        # 更新 currentFailures 中的配置名称
        current_failures = service_config.get('currentFailures', {})
        new_failures = {}
        for config_name, count in current_failures.items():
            if config_name in rename_map:
                new_failures[rename_map[config_name]] = count
                changed = True
            else:
                new_failures[config_name] = count

        if changed:
            service_config['currentFailures'] = new_failures

        # 更新 excludedConfigs 中的配置名称
        excluded_configs = service_config.get('excludedConfigs', [])
        new_excluded = []
        for config_name in excluded_configs:
            if config_name in rename_map:
                new_excluded.append(rename_map[config_name])
                changed = True
            else:
                new_excluded.append(config_name)

        if changed:
            service_config['excludedConfigs'] = new_excluded
            config.setdefault('services', {})[service] = service_config

            with open(lb_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"同步负载均衡配置名称失败: {e}")


def _cleanup_deleted_configs(service: str, old_configs: Dict[str, Any], new_configs: Dict[str, Any]) -> None:
    """清理被删除的配置在路由配置和负载均衡配置中的引用"""
    if not isinstance(old_configs, dict) or not isinstance(new_configs, dict):
        return

    # 找出被删除的配置
    deleted_configs = set(old_configs.keys()) - set(new_configs.keys())
    if not deleted_configs:
        return

    # 清理路由配置中的引用
    _cleanup_router_config_references(service, deleted_configs)
    # 清理负载均衡配置中的引用
    _cleanup_loadbalance_config_references(service, deleted_configs)


def _cleanup_router_config_references(service: str, deleted_configs: set) -> None:
    """清理路由配置中对已删除配置的引用"""
    router_config_file = DATA_DIR / 'model_router_config.json'
    if not router_config_file.exists():
        return

    try:
        with open(router_config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        changed = False

        # 清理 modelMappings 中的配置引用
        if 'modelMappings' in config and service in config['modelMappings']:
            original_mappings = config['modelMappings'][service][:]
            config['modelMappings'][service] = [
                mapping for mapping in original_mappings
                if not (mapping.get('source_type') == 'config' and mapping.get('source') in deleted_configs)
            ]
            if len(config['modelMappings'][service]) != len(original_mappings):
                changed = True

        # 清理 configMappings 中的配置引用
        if 'configMappings' in config and service in config['configMappings']:
            original_mappings = config['configMappings'][service][:]
            config['configMappings'][service] = [
                mapping for mapping in original_mappings
                if mapping.get('config') not in deleted_configs
            ]
            if len(config['configMappings'][service]) != len(original_mappings):
                changed = True

        if changed:
            with open(router_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"清理路由配置引用失败: {e}")


def _cleanup_loadbalance_config_references(service: str, deleted_configs: set) -> None:
    """清理负载均衡配置中对已删除配置的引用"""
    lb_config_file = DATA_DIR / 'lb_config.json'
    if not lb_config_file.exists():
        return

    try:
        with open(lb_config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        changed = False
        service_config = config.get('services', {}).get(service, {})

        # 清理 currentFailures 中的配置引用
        current_failures = service_config.get('currentFailures', {})
        new_failures = {
            config_name: count for config_name, count in current_failures.items()
            if config_name not in deleted_configs
        }
        if len(new_failures) != len(current_failures):
            service_config['currentFailures'] = new_failures
            changed = True

        # 清理 excludedConfigs 中的配置引用
        excluded_configs = service_config.get('excludedConfigs', [])
        new_excluded = [
            config_name for config_name in excluded_configs
            if config_name not in deleted_configs
        ]
        if len(new_excluded) != len(excluded_configs):
            service_config['excludedConfigs'] = new_excluded
            changed = True

        if changed:
            config.setdefault('services', {})[service] = service_config
            with open(lb_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"清理负载均衡配置引用失败: {e}")


def _apply_channel_renames(service: str, rename_map: Dict[str, str]) -> None:
    if not rename_map:
        return
    _rename_history_channels(service, rename_map)
    _rename_log_channels(service, rename_map)
    _sync_router_config_names(service, rename_map)
    _sync_loadbalance_config_names(service, rename_map)


def load_system_config() -> Dict[str, Any]:
    """加载系统配置"""
    if not SYSTEM_CONFIG_FILE.exists():
        default_config = {'logLimit': 50}
        save_system_config(default_config)
        return default_config

    try:
        with open(SYSTEM_CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        # 确保有默认值
        config.setdefault('logLimit', 50)
        return config
    except (json.JSONDecodeError, OSError):
        return {'logLimit': 50}


def save_system_config(config: Dict[str, Any]) -> None:
    """保存系统配置"""
    with open(SYSTEM_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def trim_logs_to_limit(limit: int) -> None:
    """裁剪日志文件到指定条数"""
    if not LOG_FILE.exists():
        return

    logs = load_logs()
    if len(logs) <= limit:
        return

    # 只保留最近的 limit 条
    trimmed_logs = logs[-limit:]

    # 重写日志文件
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        for log in trimmed_logs:
            f.write(json.dumps(log, ensure_ascii=False) + '\n')

    _trigger_usage_summary_refresh(async_mode=True)


def load_logs() -> list[Dict[str, Any]]:
    log_path = _resolve_log_path()
    if log_path is None:
        with _LOGS_CACHE_LOCK:
            _LOGS_CACHE['path'] = None
            _LOGS_CACHE['signature'] = (0, 0)
            _LOGS_CACHE['logs'] = []
        return []

    resolved_path = str(log_path.resolve())
    signature = _get_file_signature(log_path)

    with _LOGS_CACHE_LOCK:
        if _LOGS_CACHE['path'] == resolved_path and _LOGS_CACHE['signature'] == signature:
            return list(_LOGS_CACHE['logs'])

    logs: list[Dict[str, Any]] = []
    with open(log_path, 'r', encoding='utf-8') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            entry = _safe_json_load(line)
            if not entry:
                continue
            service = entry.get('service') or entry.get('usage', {}).get('service') or 'unknown'
            entry['usage'] = normalize_usage_record(service, entry.get('usage'))
            logs.append(entry)

    with _LOGS_CACHE_LOCK:
        _LOGS_CACHE['path'] = resolved_path
        _LOGS_CACHE['signature'] = signature
        _LOGS_CACHE['logs'] = logs

    return list(logs)


def load_history_usage() -> Dict[str, Dict[str, Dict[str, int]]]:
    signature = _get_file_signature(HISTORY_FILE if HISTORY_FILE.exists() else None)

    with _HISTORY_CACHE_LOCK:
        if _HISTORY_CACHE['signature'] == signature:
            return _HISTORY_CACHE['history']

    if not HISTORY_FILE.exists():
        history: Dict[str, Dict[str, Dict[str, int]]] = {}
        with _HISTORY_CACHE_LOCK:
            _HISTORY_CACHE['signature'] = signature
            _HISTORY_CACHE['history'] = history
        return history

    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        history = {}
        with _HISTORY_CACHE_LOCK:
            _HISTORY_CACHE['signature'] = signature
            _HISTORY_CACHE['history'] = history
        return history

    history: Dict[str, Dict[str, Dict[str, int]]] = {}
    for service, channels in (data or {}).items():
        if not isinstance(channels, dict):
            continue
        service_bucket: Dict[str, Dict[str, int]] = {}
        for channel, metrics in channels.items():
            normalized = empty_metrics()
            if isinstance(metrics, dict):
                merge_usage_metrics(normalized, metrics)
            service_bucket[channel] = normalized
        history[service] = service_bucket

    with _HISTORY_CACHE_LOCK:
        _HISTORY_CACHE['signature'] = signature
        _HISTORY_CACHE['history'] = history

    return history


def save_history_usage(data: Dict[str, Dict[str, Dict[str, int]]]) -> None:
    serializable = {
        service: {
            channel: {key: int(value) for key, value in metrics.items()}
            for channel, metrics in channels.items()
        }
        for service, channels in data.items()
    }
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(serializable, f, ensure_ascii=False, indent=2)

    normalized_history: Dict[str, Dict[str, Dict[str, int]]] = {}
    for service, channels in serializable.items():
        service_bucket: Dict[str, Dict[str, int]] = {}
        for channel, metrics in channels.items():
            normalized_metrics = empty_metrics()
            merge_usage_metrics(normalized_metrics, metrics)
            service_bucket[channel] = normalized_metrics
        normalized_history[service] = service_bucket

    signature = _get_file_signature(HISTORY_FILE)

    with _HISTORY_CACHE_LOCK:
        _HISTORY_CACHE['signature'] = signature
        _HISTORY_CACHE['history'] = normalized_history

    with _USAGE_SNAPSHOT_CACHE_LOCK:
        _USAGE_SNAPSHOT_CACHE['data'] = None
        _USAGE_SNAPSHOT_CACHE['history_signature'] = signature

    _trigger_usage_summary_refresh(async_mode=True)


def aggregate_usage_from_logs(logs: list[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, int]]]:
    aggregated: Dict[str, Dict[str, Dict[str, int]]] = {}
    for entry in logs:
        usage = entry.get('usage', {})
        metrics = usage.get('metrics', {})
        if not metrics:
            continue
        service = usage.get('service') or entry.get('service') or 'unknown'
        channel = entry.get('channel') or 'unknown'
        service_bucket = aggregated.setdefault(service, {})
        channel_bucket = service_bucket.setdefault(channel, empty_metrics())
        merge_usage_metrics(channel_bucket, metrics)
    return aggregated


def merge_history_usage(base: Dict[str, Dict[str, Dict[str, int]]],
                        addition: Dict[str, Dict[str, Dict[str, int]]]) -> Dict[str, Dict[str, Dict[str, int]]]:
    for service, channels in addition.items():
        service_bucket = base.setdefault(service, {})
        for channel, metrics in channels.items():
            channel_bucket = service_bucket.setdefault(channel, empty_metrics())
            merge_usage_metrics(channel_bucket, metrics)
    return base


def combine_usage_maps(current: Dict[str, Dict[str, Dict[str, int]]],
                       history: Dict[str, Dict[str, Dict[str, int]]]) -> Dict[str, Dict[str, Dict[str, int]]]:
    combined: Dict[str, Dict[str, Dict[str, int]]] = {}
    services = set(current.keys()) | set(history.keys())
    for service in services:
        combined_channels: Dict[str, Dict[str, int]] = {}
        current_channels = current.get(service, {})
        history_channels = history.get(service, {})
        all_channels = set(current_channels.keys()) | set(history_channels.keys())
        for channel in all_channels:
            metrics = empty_metrics()
            if channel in current_channels:
                merge_usage_metrics(metrics, current_channels[channel])
            if channel in history_channels:
                merge_usage_metrics(metrics, history_channels[channel])
            combined_channels[channel] = metrics
        combined[service] = combined_channels
    return combined


def compute_total_metrics(channels_map: Dict[str, Dict[str, int]]) -> Dict[str, int]:
    totals = empty_metrics()
    for metrics in channels_map.values():
        merge_usage_metrics(totals, metrics)
    return totals


def format_metrics(metrics: Dict[str, int]) -> Dict[str, str]:
    return {key: format_usage_value(metrics.get(key, 0)) for key in METRIC_KEYS}


def build_usage_snapshot() -> Dict[str, Any]:
    log_path = _resolve_log_path()
    log_key = (str(log_path.resolve()), _get_file_signature(log_path)) if log_path else (None, (0, 0))
    history_signature = _get_file_signature(HISTORY_FILE if HISTORY_FILE.exists() else None)

    with _USAGE_SNAPSHOT_CACHE_LOCK:
        cached_data = _USAGE_SNAPSHOT_CACHE['data']
        if (
            cached_data is not None
            and _USAGE_SNAPSHOT_CACHE['log_key'] == log_key
            and _USAGE_SNAPSHOT_CACHE['history_signature'] == history_signature
        ):
            return cached_data

    logs = load_logs()
    current_usage = aggregate_usage_from_logs(logs)
    history_usage = load_history_usage()
    combined_usage = combine_usage_maps(current_usage, history_usage)

    snapshot = {
        'logs': logs,
        'current_usage': current_usage,
        'history_usage': history_usage,
        'combined_usage': combined_usage
    }

    with _USAGE_SNAPSHOT_CACHE_LOCK:
        _USAGE_SNAPSHOT_CACHE['log_key'] = log_key
        _USAGE_SNAPSHOT_CACHE['history_signature'] = history_signature
        _USAGE_SNAPSHOT_CACHE['data'] = snapshot

    return snapshot

@app.route('/')
def index():
    """返回主页"""
    index_file = STATIC_DIR / 'index.html'
    return send_file(index_file)

@app.route('/static/<path:filename>')
def static_files(filename):
    """返回静态文件"""
    return send_file(STATIC_DIR / filename)

@app.route('/api/status')
def get_status():
    """获取服务状态"""
    try:
        # 直接获取实时服务状态，不依赖status.json文件
        from src.claude import ctl as claude
        from src.codex import ctl as codex
        from src.config.cached_config_manager import claude_config_manager, codex_config_manager
        
        claude_running = claude.is_running()
        claude_pid = claude.get_pid() if claude_running else None
        claude_config = claude_config_manager.active_config
        
        codex_running = codex.is_running()
        codex_pid = codex.get_pid() if codex_running else None
        codex_config = codex_config_manager.active_config
        
        # 计算配置数量
        claude_configs = len(claude_config_manager.configs)
        codex_configs = len(codex_config_manager.configs)
        total_configs = claude_configs + codex_configs
        
        usage_summary, request_count, summary_timestamp = _get_cached_usage_summary()
        
        # 计算过滤规则数量
        filter_file = Path.home() / '.clp' / 'filter.json'
        filter_count = 0
        if filter_file.exists():
            try:
                with open(filter_file, 'r', encoding='utf-8') as f:
                    filter_data = json.load(f)
                    if isinstance(filter_data, list):
                        filter_count = len(filter_data)
                    elif isinstance(filter_data, dict):
                        filter_count = 1
            except (json.JSONDecodeError, IOError):
                filter_count = 0
        
        data = {
            'services': {
                'claude': {
                    'running': claude_running,
                    'pid': claude_pid,
                    'config': claude_config
                },
                'codex': {
                    'running': codex_running,
                    'pid': codex_pid,
                    'config': codex_config
                }
            },
            'request_count': request_count,
            'config_count': total_configs,
            'filter_count': filter_count,
            'last_updated': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'usage_summary': usage_summary,
            'summary_timestamp': summary_timestamp
        }
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/<service>', methods=['GET'])
def get_config(service):
    """获取配置文件内容"""
    try:
        if service not in ['claude', 'codex']:
            return jsonify({'error': 'Invalid service name'}), 400
        
        config_file = Path.home() / '.clp' / f'{service}.json'
        config_file.parent.mkdir(parents=True, exist_ok=True)

        if not config_file.exists():
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump({}, f, ensure_ascii=False, indent=2)

        content = config_file.read_text(encoding='utf-8')
        if not content.strip():
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump({}, f, ensure_ascii=False, indent=2)
            content = config_file.read_text(encoding='utf-8')

        return jsonify({'content': content})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/<service>', methods=['POST'])
def save_config(service):
    """保存配置文件内容"""
    try:
        if service not in ['claude', 'codex']:
            return jsonify({'error': 'Invalid service name'}), 400
        
        data = request.get_json()
        content = data.get('content', '')

        if not content:
            return jsonify({'error': 'Content cannot be empty'}), 400

        # 验证JSON格式
        try:
            new_configs = json.loads(content)
        except json.JSONDecodeError as e:
            return jsonify({'error': f'Invalid JSON format: {str(e)}'}), 400

        config_file = Path.home() / '.clp' / f'{service}.json'
        old_content = None
        old_configs: Dict[str, Any] = {}

        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                old_content = f.read()
            try:
                old_configs = json.loads(old_content)
            except json.JSONDecodeError:
                old_configs = {}

        rename_map = _detect_config_renames(old_configs, new_configs)

        try:
            # 直接写入新内容
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(content)

            _apply_channel_renames(service, rename_map)
            _cleanup_deleted_configs(service, old_configs, new_configs)
        except Exception as exc:
            # 恢复旧配置，避免部分成功
            if old_content is not None:
                with open(config_file, 'w', encoding='utf-8') as f:
                    f.write(old_content)
            else:
                config_file.unlink(missing_ok=True)
            return jsonify({'error': f'配置保存失败: {exc}'}), 500

        return jsonify({'success': True, 'message': f'{service}配置保存成功'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/filter', methods=['GET'])
def get_filter():
    """获取过滤规则文件内容"""
    try:
        filter_file = Path.home() / '.clp' / 'filter.json'
        
        if not filter_file.exists():
            # 创建默认的过滤规则文件
            default_content = '[\n  {\n    "source": "example_text",\n    "target": "replacement_text",\n    "op": "replace"\n  }\n]'
            return jsonify({'content': default_content})
        
        with open(filter_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({'content': content})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/filter', methods=['POST'])
def save_filter():
    """保存过滤规则文件内容"""
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        if not content:
            return jsonify({'error': 'Content cannot be empty'}), 400
        
        # 验证JSON格式
        try:
            filter_data = json.loads(content)
            # 验证过滤规则格式
            if isinstance(filter_data, list):
                for rule in filter_data:
                    if not isinstance(rule, dict):
                        return jsonify({'error': 'Each filter rule must be an object'}), 400
                    if 'source' not in rule or 'op' not in rule:
                        return jsonify({'error': 'Each rule must have "source" and "op" fields'}), 400
                    if rule['op'] not in ['replace', 'remove']:
                        return jsonify({'error': 'op must be "replace" or "remove"'}), 400
                    if rule['op'] == 'replace' and 'target' not in rule:
                        return jsonify({'error': 'replace operation requires "target" field'}), 400
            elif isinstance(filter_data, dict):
                if 'source' not in filter_data or 'op' not in filter_data:
                    return jsonify({'error': 'Rule must have "source" and "op" fields'}), 400
                if filter_data['op'] not in ['replace', 'remove']:
                    return jsonify({'error': 'op must be "replace" or "remove"'}), 400
                if filter_data['op'] == 'replace' and 'target' not in filter_data:
                    return jsonify({'error': 'replace operation requires "target" field'}), 400
            else:
                return jsonify({'error': 'Filter data must be an object or array of objects'}), 400
                
        except json.JSONDecodeError as e:
            return jsonify({'error': f'Invalid JSON format: {str(e)}'}), 400
        
        filter_file = Path.home() / '.clp' / 'filter.json'
        
        # 直接写入新内容，不进行备份
        with open(filter_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return jsonify({'success': True, 'message': '过滤规则保存成功'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """获取请求日志"""
    try:
        logs = load_logs()
        return jsonify(logs[-10:][::-1])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/all')
def get_all_logs():
    """获取所有请求日志"""
    try:
        logs = load_logs()
        return jsonify(logs[::-1])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['DELETE'])
def clear_logs():
    """清空所有日志"""
    try:
        logs = load_logs()
        if logs:
            aggregated = aggregate_usage_from_logs(logs)
            if aggregated:
                history_usage = load_history_usage()
                merged = merge_history_usage(history_usage, aggregated)
                save_history_usage(merged)

        log_path = LOG_FILE if LOG_FILE.exists() else (
            OLD_LOG_FILE if OLD_LOG_FILE.exists() else LOG_FILE
        )
        log_path.write_text('', encoding='utf-8')
        if log_path != LOG_FILE:
            LOG_FILE.touch(exist_ok=True)

        _trigger_usage_summary_refresh(async_mode=True)

        return jsonify({'success': True, 'message': '日志已清空'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/usage/details')
def get_usage_details():
    """返回合并后的usage明细"""
    try:
        snapshot = build_usage_snapshot()
        combined_usage = snapshot['combined_usage']

        services_payload: Dict[str, Any] = {}
        for service, channels in combined_usage.items():
            overall_metrics = compute_total_metrics(channels)
            services_payload[service] = {
                'overall': {
                    'metrics': overall_metrics,
                    'formatted': format_metrics(overall_metrics)
                },
                'channels': {
                    channel: {
                        'metrics': metrics,
                        'formatted': format_metrics(metrics)
                    }
                    for channel, metrics in channels.items()
                }
            }

        totals_metrics = empty_metrics()
        for service_data in services_payload.values():
            merge_usage_metrics(totals_metrics, service_data['overall']['metrics'])

        response = {
            'totals': {
                'metrics': totals_metrics,
                'formatted': format_metrics(totals_metrics)
            },
            'services': services_payload
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/usage/clear', methods=['DELETE'])
def clear_usage():
    """清空Token使用记录"""
    try:
        # 1. 先清空日志（复用现有功能）
        logs = load_logs()
        if logs:
            aggregated = aggregate_usage_from_logs(logs)
            if aggregated:
                history_usage = load_history_usage()
                merged = merge_history_usage(history_usage, aggregated)
                save_history_usage(merged)

        log_path = LOG_FILE if LOG_FILE.exists() else (
            OLD_LOG_FILE if OLD_LOG_FILE.exists() else LOG_FILE
        )
        log_path.write_text('', encoding='utf-8')
        if log_path != LOG_FILE:
            LOG_FILE.touch(exist_ok=True)

        # 2. 清空 history_usage.json 中的所有数值
        save_history_usage({"claude": {}, "codex":{}})

        _trigger_usage_summary_refresh(async_mode=True)

        return jsonify({'success': True, 'message': 'Token使用记录已清空'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/switch-config', methods=['POST'])
def switch_config():
    """切换激活配置"""
    try:
        data = request.get_json()
        service = data.get('service')
        config = data.get('config')

        if not service or not config:
            return jsonify({'error': 'Missing service or config parameter'}), 400

        if service not in ['claude', 'codex']:
            return jsonify({'error': 'Invalid service name'}), 400

        # 导入对应的配置管理器
        if service == 'claude':
            from src.config.cached_config_manager import claude_config_manager as config_manager
        else:
            from src.config.cached_config_manager import codex_config_manager as config_manager

        # 切换配置
        if config_manager.set_active_config(config):
            # 验证配置确实已切换
            actual_config = config_manager.active_config
            if actual_config == config:
                return jsonify({
                    'success': True,
                    'message': f'{service}配置已切换到: {config}',
                    'active_config': actual_config
                })
            else:
                return jsonify({
                    'success': False,
                    'message': f'配置切换验证失败，当前配置: {actual_config}'
                })
        else:
            return jsonify({'success': False, 'message': f'配置{config}不存在'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/routing/config', methods=['GET'])
def get_routing_config():
    """获取模型路由配置"""
    try:
        routing_config_file = DATA_DIR / 'model_router_config.json'
        
        # 如果配置文件不存在，返回默认配置
        if not routing_config_file.exists():
            default_config = {
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
            return jsonify({'config': default_config})
        
        with open(routing_config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        return jsonify({'config': config})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/routing/config', methods=['POST'])
def save_routing_config():
    """保存模型路由配置"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No configuration data provided'}), 400
        
        # 验证配置格式
        required_fields = ['mode', 'modelMappings', 'configMappings']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # 验证模式
        if data['mode'] not in ['default', 'model-mapping', 'config-mapping']:
            return jsonify({'error': 'Invalid routing mode'}), 400
        
        # 验证映射格式
        for service in ['claude', 'codex']:
            if service not in data['modelMappings']:
                data['modelMappings'][service] = []
            if service not in data['configMappings']:
                data['configMappings'][service] = []
        
        routing_config_file = DATA_DIR / 'model_router_config.json'
        
        # 保存配置
        with open(routing_config_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return jsonify({'success': True, 'message': '路由配置保存成功'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """测试API端点连通性"""
    try:
        data = request.get_json()
        service = data.get('service')
        model = data.get('model')
        base_url = data.get('base_url')
        auth_token = data.get('auth_token')
        api_key = data.get('api_key')
        extra_params = data.get('extra_params', {})

        # 参数验证
        if not service:
            return jsonify({'error': 'Missing service parameter'}), 400
        if not model:
            return jsonify({'error': 'Missing model parameter'}), 400
        if not base_url:
            return jsonify({'error': 'Missing base_url parameter'}), 400

        if service not in ['claude', 'codex']:
            return jsonify({'error': 'Invalid service name'}), 400

        # 验证至少有一种认证方式
        if not auth_token and not api_key:
            return jsonify({'error': 'Missing authentication (auth_token or api_key)'}), 400

        # 获取对应的proxy实例
        if service == 'claude':
            from src.claude.proxy import proxy_service
        else:
            from src.codex.proxy import proxy_service

        # 调用测试方法
        result = proxy_service.test_endpoint(
            model=model,
            base_url=base_url,
            auth_token=auth_token,
            api_key=api_key,
            extra_params=extra_params
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'status_code': None,
            'response_text': str(e),
            'target_url': None,
            'error_message': str(e)
        }), 500

@app.route('/api/loadbalance/config', methods=['GET'])
def get_loadbalance_config():
    """获取负载均衡配置"""
    try:
        lb_config_file = DATA_DIR / 'lb_config.json'

        def default_section():
            return {
                'failureThreshold': 3,
                'autoResetMinutes': 10,
                'currentFailures': {},
                'excludedConfigs': [],
                'excludedTimestamps': {},
                'manualDisabledUntil': {}
            }

        default_config = {
            'mode': 'active-first',
            'services': {
                'claude': default_section(),
                'codex': default_section()
            }
        }

        if not lb_config_file.exists():
            return jsonify({'config': default_config})

        with open(lb_config_file, 'r', encoding='utf-8') as f:
            raw_config = json.load(f)

        config = {
            'mode': raw_config.get('mode', 'active-first'),
            'services': {
                'claude': default_section(),
                'codex': default_section()
            }
        }

        for service in ['claude', 'codex']:
            section = raw_config.get('services', {}).get(service, {})
            threshold = section.get('failureThreshold', section.get('failover_count', 3))
            try:
                threshold = int(threshold)
                if threshold <= 0:
                    threshold = 3
            except (TypeError, ValueError):
                threshold = 3

            failures = section.get('currentFailures', section.get('current_failures', {}))
            if not isinstance(failures, dict):
                failures = {}
            normalized_failures = {}
            for name, count in failures.items():
                try:
                    numeric = int(count)
                except (TypeError, ValueError):
                    numeric = 0
                normalized_failures[str(name)] = max(numeric, 0)

            excluded = section.get('excludedConfigs', section.get('excluded_configs', []))
            if not isinstance(excluded, list):
                excluded = []
            normalized_excluded = [str(item) for item in excluded if isinstance(item, str)]

            auto_reset = section.get('autoResetMinutes', section.get('auto_reset_minutes', 10))
            try:
                auto_reset = int(auto_reset)
                if auto_reset < 0:
                    auto_reset = 0
            except (TypeError, ValueError):
                auto_reset = 10

            timestamps = section.get('excludedTimestamps', section.get('excluded_timestamps', {}))
            if not isinstance(timestamps, dict):
                timestamps = {}
            normalized_timestamps = {}
            for name, ts in timestamps.items():
                try:
                    numeric_ts = float(ts)
                except (TypeError, ValueError):
                    continue
                if name in normalized_excluded and numeric_ts > 0:
                    normalized_timestamps[str(name)] = numeric_ts

            config['services'][service] = {
                'failureThreshold': threshold,
                'currentFailures': normalized_failures,
                'excludedConfigs': normalized_excluded,
                'autoResetMinutes': auto_reset,
                'excludedTimestamps': normalized_timestamps,
                'manualDisabledUntil': {
                    str(name): str(value).strip()
                    for name, value in (section.get('manualDisabledUntil', section.get('manual_disabled_until', {})) or {}).items()
                    if isinstance(name, str) and str(value).strip()
                },
            }

        return jsonify({'config': config})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/loadbalance/config', methods=['POST'])
def save_loadbalance_config():
    """保存负载均衡配置"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No configuration data provided'}), 400

        mode = data.get('mode')
        if mode not in ['active-first', 'weight-based']:
            return jsonify({'error': 'Invalid loadbalance mode'}), 400

        services = data.get('services', {})
        lb_config_file = DATA_DIR / 'lb_config.json'
        normalized = {
            'mode': mode,
            'services': {}
        }

        existing_config = {}
        if lb_config_file.exists():
            try:
                with open(lb_config_file, 'r', encoding='utf-8') as f:
                    existing_config = json.load(f)
            except Exception:
                existing_config = {}

        for service in ['claude', 'codex']:
            section = services.get(service, {})
            threshold = section.get('failureThreshold', 3)
            try:
                threshold = int(threshold)
                if threshold <= 0:
                    threshold = 3
            except (TypeError, ValueError):
                return jsonify({'error': f'Invalid failureThreshold for service {service}'}), 400

            failures = section.get('currentFailures', {})
            if not isinstance(failures, dict):
                return jsonify({'error': f'currentFailures for service {service} must be an object'}), 400
            normalized_failures = {}
            for name, count in failures.items():
                try:
                    numeric = int(count)
                except (TypeError, ValueError):
                    return jsonify({'error': f'Failure count for {service}:{name} must be integer'}), 400
                normalized_failures[str(name)] = max(numeric, 0)

            excluded = section.get('excludedConfigs', [])
            if excluded is None:
                excluded = []
            if not isinstance(excluded, list):
                return jsonify({'error': f'excludedConfigs for service {service} must be an array'}), 400
            normalized_excluded = [str(item) for item in excluded if isinstance(item, str)]

            auto_reset = section.get('autoResetMinutes', section.get('auto_reset_minutes', 10))
            try:
                auto_reset = int(auto_reset)
            except (TypeError, ValueError):
                return jsonify({'error': f'autoResetMinutes for service {service} must be integer'}), 400
            if auto_reset < 0:
                return jsonify({'error': f'autoResetMinutes for service {service} must be >= 0'}), 400

            existing_section = existing_config.get('services', {}).get(service, {}) if isinstance(existing_config, dict) else {}
            existing_timestamps = existing_section.get('excludedTimestamps', {})
            if not isinstance(existing_timestamps, dict):
                existing_timestamps = {}
            normalized_timestamps = {}
            for name in normalized_excluded:
                raw_ts = existing_timestamps.get(name)
                try:
                    numeric_ts = float(raw_ts)
                except (TypeError, ValueError):
                    continue
                if numeric_ts > 0:
                    normalized_timestamps[name] = numeric_ts

            normalized['services'][service] = {
                'failureThreshold': threshold,
                'currentFailures': normalized_failures,
                'excludedConfigs': normalized_excluded,
                'autoResetMinutes': auto_reset,
                'excludedTimestamps': normalized_timestamps,
                'manualDisabledUntil': {}
            }

            manual_disabled = section.get('manualDisabledUntil', section.get('manual_disabled_until', {}))
            if manual_disabled is None:
                manual_disabled = {}
            if not isinstance(manual_disabled, dict):
                return jsonify({'error': f'manualDisabledUntil for service {service} must be an object'}), 400

            normalized_manual = {}
            for name, value in manual_disabled.items():
                if not isinstance(name, str):
                    continue
                date_str = str(value).strip()
                if date_str:
                    normalized_manual[name] = date_str

            normalized['services'][service]['manualDisabledUntil'] = normalized_manual

        with open(lb_config_file, 'w', encoding='utf-8') as f:
            json.dump(normalized, f, ensure_ascii=False, indent=2)

        return jsonify({'success': True, 'message': '负载均衡配置保存成功'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/loadbalance/reset-failures', methods=['POST'])
def reset_loadbalance_failures():
    """重置负载均衡失败计数"""
    try:
        data = request.get_json()
        service = data.get('service')
        config_name = data.get('config_name')  # 可选，如果不提供则重置所有

        if not service or service not in ['claude', 'codex']:
            return jsonify({'error': 'Invalid service parameter'}), 400

        lb_config_file = DATA_DIR / 'lb_config.json'

        # 如果配置文件不存在，直接返回成功
        if not lb_config_file.exists():
            return jsonify({'success': True, 'message': '无需重置'})

        with open(lb_config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)

        services = config.setdefault('services', {})
        service_config = services.setdefault(service, {
            'failureThreshold': 3,
            'autoResetMinutes': 10,
            'currentFailures': {},
            'excludedConfigs': [],
            'excludedTimestamps': {}
        })

        current_failures = service_config.setdefault('currentFailures', {})
        excluded_configs = service_config.setdefault('excludedConfigs', [])
        excluded_timestamps = service_config.setdefault('excludedTimestamps', {})
        service_config.setdefault('manualDisabledUntil', {})

        if config_name:
            key = str(config_name)
            if key in current_failures:
                current_failures[key] = 0
            if key in excluded_configs:
                excluded_configs.remove(key)
            if key in excluded_timestamps:
                excluded_timestamps.pop(key, None)
            message = f'已重置 {service} 服务的 {key} 配置失败计数'
        else:
            service_config['currentFailures'] = {}
            service_config['excludedConfigs'] = []
            service_config['excludedTimestamps'] = {}
            message = f'已重置 {service} 服务的所有失败计数'

        with open(lb_config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

        return jsonify({'success': True, 'message': message})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/config', methods=['GET'])
def get_system_config():
    """获取系统配置"""
    try:
        config = load_system_config()
        return jsonify({'config': config})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/config', methods=['POST'])
def update_system_config():
    """更新系统配置"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No configuration data provided'}), 400

        # 验证 logLimit
        log_limit = data.get('logLimit')
        if log_limit is not None:
            if not isinstance(log_limit, int) or log_limit not in [10, 30, 50, 100]:
                return jsonify({'error': 'Invalid logLimit value'}), 400

        # 保存配置
        save_system_config(data)

        # 如果修改了 logLimit，立即裁剪日志
        if log_limit is not None:
            trim_logs_to_limit(log_limit)

        return jsonify({'success': True, 'message': '系统配置保存成功'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def start_ui_server(port=3300):
    """启动UI服务器并打开浏览器"""
    print(f"启动Web UI服务器在端口 {port}")

    # 启动Flask应用
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    start_ui_server()
