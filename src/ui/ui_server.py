import json
import webbrowser
import time
from pathlib import Path
from typing import Any, Dict
from flask import Flask, jsonify, send_file, request, make_response
import hmac
import hashlib
import base64
import os

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

if OLD_LOG_FILE.exists() and not LOG_FILE.exists():
    try:
        OLD_LOG_FILE.rename(LOG_FILE)
    except OSError:
        pass

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path='/static')

# ---- UI 鉴权（账号密码 + JWT）----
AUTH_FILE = Path.home() / '.clp' / 'auth_config.json'

def _load_unified_config() -> Dict[str, Any]:
    try:
        if AUTH_FILE.exists():
            return json.loads(AUTH_FILE.read_text(encoding='utf-8') or '{}')
    except Exception:
        pass
    return {}

def _save_unified_config(data: Dict[str, Any]) -> None:
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

def _get_ui_jwt_secret() -> str:
    """优先从统一配置读取 UI JWT 秘钥，其次环境变量，最后开发默认值。
    同时兼容迁移期：如果配置未写入，建议在启动时调用 ensure_ui_security_bootstrap 写入随机密钥。
    """
    try:
        cfg = _load_unified_config()
        secret = cfg.get('ui_jwt_secret') or cfg.get('CLP_UI_JWT_SECRET')
        if isinstance(secret, str) and secret.strip():
            return secret.strip()
    except Exception:
        pass
    return os.environ.get('CLP_UI_JWT_SECRET', 'clp-dev-secret')

UI_JWT_SECRET = _get_ui_jwt_secret()

def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 120000)
    return base64.b64encode(dk).decode('ascii')

def _verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode('ascii'))
        calc = _hash_password(password, salt)
        return hmac.compare_digest(calc, hash_b64)
    except Exception:
        return False

def ensure_ui_security_bootstrap(print_fn=print) -> None:
    """系统启动前的安全初始化：
    - 若未持久化管理员，则写入默认管理员（admin/admin 或取环境变量）
    - 若未配置 ui_jwt_secret，则生成随机密钥
    - 默认启用 UI 鉴权（将 'ui' 加入 enabled）
    - 打印命令行提示
    """
    try:
        cfg = _load_unified_config()
        changed = False
        created_admin = False
        created_secret = False
        enabled_ui = False

        # 1) 管理员
        ua = cfg.get('ui_admin') or {}
        if not (isinstance(ua, dict) and ua.get('username') and ua.get('password_hash') and ua.get('salt')):
            username = os.environ.get('CLP_UI_USERNAME', 'admin')
            password = os.environ.get('CLP_UI_PASSWORD', 'admin')
            salt = os.urandom(16)
            salt_b64 = base64.b64encode(salt).decode('ascii')
            hash_b64 = _hash_password(password, salt)
            cfg['ui_admin'] = {'username': username, 'password_hash': hash_b64, 'salt': salt_b64}
            changed = True
            created_admin = True

        # 2) JWT secret
        if not (isinstance(cfg.get('ui_jwt_secret'), str) and cfg.get('ui_jwt_secret').strip()):
            # 32 bytes URL-safe base64 (no padding)
            rnd = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
            cfg['ui_jwt_secret'] = rnd
            changed = True
            created_secret = True

        # 3) 启用 UI 鉴权
        enabled = cfg.get('enabled')
        if isinstance(enabled, list):
            if 'ui' not in enabled:
                enabled.append('ui')
                changed = True
                enabled_ui = True
        else:
            cfg['enabled'] = ['ui']
            changed = True
            enabled_ui = True

        if changed:
            _save_unified_config(cfg)
            # 更新进程内 JWT 秘钥缓存
            global UI_JWT_SECRET
            UI_JWT_SECRET = cfg.get('ui_jwt_secret') or UI_JWT_SECRET

        # 打印提示
        if created_admin:
            print_fn('[auth] 已生成默认管理员账号，并启用UI鉴权（请尽快在面板中修改密码）。')
        if created_secret:
            print_fn('[auth] 已生成 UI JWT 秘钥。')
        if enabled_ui and not created_admin and not created_secret:
            print_fn('[auth] 已确保 UI 鉴权启用。')
    except Exception as e:
        print_fn(f'[auth] 启动安全初始化失败: {e}')


def _ensure_default_admin_persisted() -> None:
    """当启用 UI 鉴权时，若未持久化管理员，则写入默认管理员到 auth_config.json。

    默认取环境变量 CLP_UI_USERNAME/CLP_UI_PASSWORD；若未设置，则使用 admin/admin。
    密码以 PBKDF2 + salt 的方式持久化（不回写明文）。
    """
    try:
        cfg = _load_unified_config()
        ua = cfg.get('ui_admin') or {}
        if isinstance(ua, dict) and ua.get('username') and ua.get('password_hash') and ua.get('salt'):
            return  # 已持久化

        username = os.environ.get('CLP_UI_USERNAME', 'admin')
        password = os.environ.get('CLP_UI_PASSWORD', 'admin')
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode('ascii')
        hash_b64 = _hash_password(password, salt)
        cfg['ui_admin'] = {'username': username, 'password_hash': hash_b64, 'salt': salt_b64}
        _save_unified_config(cfg)
    except Exception:
        # 避免影响主流程
        pass

def _get_ui_auth() -> Dict[str, str]:
    """读取 UI 管理员账号与口令来源。

    优先文件 ~/.clp/ui_auth.json {username, password_hash, salt}；否则回退到环境变量（明文）。
    返回：{"username": str, "password": str} 或 {"username": str, "password_hash": str, "salt": str}
    """
    # 单一文件
    try:
        cfg = _load_unified_config()
        ua = cfg.get('ui_admin')
        if isinstance(ua, dict) and ua.get('username') and ua.get('password_hash') and ua.get('salt'):
            return ua
    except Exception:
        pass
    # 环境变量回退（明文）
    return {
        'username': os.environ.get('CLP_UI_USERNAME', 'admin'),
        'password': os.environ.get('CLP_UI_PASSWORD', 'admin'),
    }


def _get_auth_mode() -> int:
    """读取鉴权模式：0关闭，1全部，2仅UI，3仅codex，4仅claude。

    来源优先级：环境变量 CLP_AUTH_MODE > 文件 ~/.clp/auth_config.json {"mode": N}
    无配置默认 0。
    """
    try:
        val = os.environ.get('CLP_AUTH_MODE')
        if val is not None:
            return int(val)
    except Exception:
        pass
    try:
        cfg = Path.home() / '.clp' / 'auth_config.json'
        if cfg.exists():
            with open(cfg, 'r', encoding='utf-8') as f:
                data = json.load(f)
            m = data.get('mode')
            if isinstance(m, int):
                return m
    except Exception:
        pass
    return 0

def _is_ui_auth_required() -> bool:
    mode = _get_auth_mode()
    # 兼容 list 形式配置
    try:
        cfg = _load_unified_config()
        enabled = cfg.get('enabled')
        if isinstance(enabled, list):
            return 'ui' in enabled
    except Exception:
        pass
    return mode in (1, 2)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode('ascii'))


def _jwt_encode(payload: Dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _jwt_decode(token: str, secret: str) -> Dict[str, Any]:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('invalid token')
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    expected = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    actual = _b64url_decode(sig_b64)
    if not hmac.compare_digest(expected, actual):
        raise ValueError('bad signature')
    payload = json.loads(_b64url_decode(payload_b64))
    exp = payload.get('exp')
    if isinstance(exp, (int, float)) and time.time() > float(exp):
        raise ValueError('token expired')
    return payload


def _verify_ui_auth() -> bool:
    """校验UI接口 JWT 鉴权。

    - 仅保护 /api/* 路由（除 /api/login）；首页与静态资源不鉴权。
    - 预检 OPTIONS 放行。
    - 需要请求头 Authorization: Bearer <jwt>
    """
    if not request.path.startswith('/api/'):
        return True
    if request.path == '/api/login':
        return True
    if request.method == 'OPTIONS':
        return True
    if not _is_ui_auth_required():
        return True

    token = request.cookies.get('ui_jwt')
    if not token:
        auth = request.headers.get('Authorization') or request.headers.get('authorization')
        if not isinstance(auth, str) or not auth.lower().startswith('bearer '):
            return False
        token = auth[7:].strip()
    if not token:
        return False
    try:
        _jwt_decode(token, UI_JWT_SECRET)
        return True
    except Exception:
        return False


@app.before_request
def _api_auth_guard():
    if not _verify_ui_auth():
        return jsonify({'error': 'Unauthorized'}), 401


@app.route('/login')
def login_page():
    login_file = STATIC_DIR / 'login.html'
    return send_file(login_file)


# ---------- Auth Settings APIs ----------

def _read_enabled_services() -> list[str]:
    # 优先文件 enabled 列表；其次整数 mode；最后空
    try:
        cfg = _load_unified_config()
        enabled = cfg.get('enabled')
        if isinstance(enabled, list):
            return [s for s in enabled if s in ('ui', 'codex', 'claude')]
    except Exception:
        pass
    # 环境变量兜底
    try:
        enabled_env = os.environ.get('CLP_AUTH_ENABLED')
        if enabled_env:
            items = [x.strip() for x in enabled_env.split(',') if x.strip()]
            return [s for s in items if s in ('ui', 'codex', 'claude')]
    except Exception:
        pass
    mode = _get_auth_mode()
    if mode == 1:
        return ['ui', 'codex', 'claude']
    if mode == 2:
        return ['ui']
    if mode == 3:
        return ['codex']
    if mode == 4:
        return ['claude']
    return []


def _write_enabled_services(enabled: list[str]) -> None:
    data = _load_unified_config()
    data['enabled'] = [s for s in enabled if s in ('ui', 'codex', 'claude')]
    _save_unified_config(data)


def _read_proxy_auth_flags() -> dict:
    # 返回是否已配置，用于 UI 展示；不回传明文
    # 规则：服务标识为“本服务已设置”或“共享已设置”任一即视为已配置
    res = {
        'shared': {'has_auth_token': False, 'has_api_key': False},
        'claude': {'has_auth_token': False, 'has_api_key': False},
        'codex': {'has_auth_token': False, 'has_api_key': False}
    }
    try:
        cfg = _load_unified_config()
        proxy = cfg.get('proxy') or {}
        # 读取分开鉴权标志
        separate = bool(proxy.get('separate'))
        shared = proxy.get('shared') or {}
        if isinstance(shared, dict):
            if shared.get('auth_token'):
                res['shared']['has_auth_token'] = True
            if shared.get('api_key'):
                res['shared']['has_api_key'] = True

        for svc in ('claude', 'codex'):
            svc_data = proxy.get(svc) or {}
            has_token = False
            has_key = False
            if isinstance(svc_data, dict):
                has_token = bool(svc_data.get('auth_token'))
                has_key = bool(svc_data.get('api_key'))
            # 不再与共享状态合并：服务仅显示自身配置情况
            res[svc]['has_auth_token'] = has_token
            res[svc]['has_api_key'] = has_key
    except Exception:
        pass
    return res


def _write_proxy_auth_updates(updates: dict) -> None:
    # updates: { shared?: {auth_token?, api_key?}, claude?: {...}, codex?: {...} }
    cfg = _load_unified_config()
    proxy = cfg.get('proxy') or {}

    def _apply(target_key: str):
        patch = updates.get(target_key)
        if not isinstance(patch, dict):
            return
        cur = proxy.get(target_key) or {}
        for key in ('auth_token', 'api_key'):
            if key in patch:
                val = patch.get(key)
                # 允许设置为空串以清空
                if isinstance(val, str):
                    cur[key] = val
        # 透传 disabled 标记（仅影响UI展示）
        if isinstance(patch, dict) and 'disabled' in patch:
            cur['disabled'] = bool(patch.get('disabled'))
        proxy[target_key] = cur

    # 支持 shared 独立字段，不向各服务回填（YAGNI）
    for key in ('shared', 'claude', 'codex'):
        _apply(key)

    # 写入分开鉴权模式标志：仅标记，不清空任何密钥
    if 'separate' in updates:
        proxy['separate'] = bool(updates.get('separate'))
        # 同步 disabled 标记，供前端隐藏
        shared = proxy.setdefault('shared', {})
        codex = proxy.setdefault('codex', {})
        claude = proxy.setdefault('claude', {})
        if proxy['separate']:
            shared['disabled'] = True
            codex['disabled'] = False
            claude['disabled'] = False
        else:
            shared['disabled'] = False
            codex['disabled'] = True
            claude['disabled'] = True

    cfg['proxy'] = proxy
    _save_unified_config(cfg)


def _get_active_shared_key(cfg: Dict[str, Any]) -> str | None:
    proxy = cfg.get('proxy') or {}
    shared = proxy.get('shared') or {}
    # 新结构优先：keys 数组
    keys = shared.get('keys')
    if isinstance(keys, list) and keys:
        for k in keys:
            if isinstance(k, dict) and k.get('active') and isinstance(k.get('value'), str):
                return k.get('value')
        # fallback to first
        v = keys[0].get('value') if isinstance(keys[0], dict) else None
        if isinstance(v, str):
            return v
    return None


def _get_active_service_key(cfg: Dict[str, Any], service: str) -> str | None:
    proxy = cfg.get('proxy') or {}
    bucket = proxy.get(service) or {}
    keys = bucket.get('keys')
    if isinstance(keys, list) and keys:
        for k in keys:
            if isinstance(k, dict) and k.get('active') and isinstance(k.get('value'), str):
                return k.get('value')
        if isinstance(keys[0], dict):
            v = keys[0].get('value')
            if isinstance(v, str):
                return v
    return None




def _ensure_default_shared_key(cfg: Dict[str, Any], remark: str = '默认') -> bool:
    """若共享列表为空则生成一个默认密钥（不写入旧镜像字段）。"""
    proxy = cfg.setdefault('proxy', {})
    shared = proxy.setdefault('shared', {})
    keys = shared.get('keys')
    if isinstance(keys, list) and any(isinstance(k, dict) and k.get('value') for k in keys):
        return False
    rnd = base64.urlsafe_b64encode(os.urandom(24)).decode('ascii').rstrip('=')
    value = f"key_{rnd}"
    shared['keys'] = [{
        'id': base64.urlsafe_b64encode(os.urandom(12)).decode('ascii').rstrip('='),
        'value': value,
        'remark': remark,
        'active': True,
        'created_at': int(time.time())
    }]
    cfg['proxy'] = proxy
    return True


def _ensure_default_service_key(cfg: Dict[str, Any], service: str, remark: str = '默认') -> bool:
    """若服务级列表为空则为指定服务生成一个默认密钥。

    Args:
        cfg: 已加载的统一配置 dict
        service: 'claude' 或 'codex'
        remark: 备注
    Returns:
        bool: 是否写入了新密钥
    """
    if service not in ('claude', 'codex'):
        return False
    proxy = cfg.setdefault('proxy', {})
    bucket = proxy.setdefault(service, {})
    keys = bucket.get('keys')
    if isinstance(keys, list) and any(isinstance(k, dict) and k.get('value') for k in keys):
        return False
    if not isinstance(keys, list):
        keys = []
        bucket['keys'] = keys
    kid = base64.urlsafe_b64encode(os.urandom(12)).decode('ascii').rstrip('=')
    rnd = base64.urlsafe_b64encode(os.urandom(24)).decode('ascii').rstrip('=')
    value = f"key_{rnd}"
    keys.append({
        'id': kid,
        'value': value,
        'remark': remark,
        'active': True,
        'created_at': int(time.time()),
    })
    cfg['proxy'] = proxy
    return True
@app.route('/api/auth/settings', methods=['GET'])
def get_auth_settings():
    try:
        enabled = _read_enabled_services()
        proxy_flags = _read_proxy_auth_flags()
        # 同时返回分开鉴权模式
        separate = False
        try:
            cfg = _load_unified_config()
            separate = bool((cfg.get('proxy') or {}).get('separate'))
        except Exception:
            pass
        return jsonify({'enabled': enabled, 'proxy': proxy_flags, 'separate': separate})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/settings', methods=['POST'])
def save_auth_settings():
    try:
        data = request.get_json(force=True, silent=True) or {}
        enabled = data.get('enabled')
        if isinstance(enabled, list):
            _write_enabled_services(enabled)
            # 若启用 UI 鉴权，确保默认管理员已持久化
            if 'ui' in enabled:
                _ensure_default_admin_persisted()
        proxy_updates = data.get('proxy')
        if isinstance(proxy_updates, dict):
            _write_proxy_auth_updates(proxy_updates)
        # 自动生成密钥：仅在“共享鉴权”模式下，若共享密钥列表为空则生成一个默认密钥；
        # 分开鉴权模式下不为各服务自动生成密钥（按需手动创建）。
        try:
            cfg = _load_unified_config()
            separate = bool((cfg.get('proxy') or {}).get('separate'))
            changed = False
            if separate:
                # 分开鉴权：若各服务密钥为空，则为每个服务生成一个默认密钥
                if _ensure_default_service_key(cfg, 'claude', '默认'): changed = True
                if _ensure_default_service_key(cfg, 'codex', '默认'): changed = True
            else:
                # 共享鉴权：若共享密钥为空则生成一个默认密钥
                if _ensure_default_shared_key(cfg, '默认'): changed = True
            if changed:
                _save_unified_config(cfg)
        except Exception:
            pass
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---- 服务级密钥列表 API（仅在分开鉴权模式下前端展示；后端始终可用） ----

@app.route('/api/auth/service-keys', methods=['GET'])
def list_service_keys():
    try:
        service = request.args.get('service')
        if service not in ('claude', 'codex'):
            return jsonify({'error': 'Invalid service'}), 400
        cfg = _load_unified_config()
        bucket = (cfg.get('proxy') or {}).get(service) or {}
        keys = [k for k in (bucket.get('keys') or []) if isinstance(k, dict)]
        meta = []
        for k in keys:
            meta.append({
                'id': k.get('id'),
                'remark': k.get('remark'),
                'value': k.get('value') or '',
                'created_at': k.get('created_at')
            })
        return jsonify({'keys': meta})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/service-key', methods=['GET'])
def get_service_key_value():
    try:
        service = request.args.get('service')
        if service not in ('claude', 'codex'):
            return jsonify({'error': 'Invalid service'}), 400
        key_id = request.args.get('id')
        cfg = _load_unified_config()
        bucket = (cfg.get('proxy') or {}).get(service) or {}
        keys = bucket.get('keys') or []
        if key_id:
            for k in keys:
                if isinstance(k, dict) and k.get('id') == key_id:
                    return jsonify({'value': k.get('value') or ''})
            return jsonify({'error': 'Not found'}), 404
        val = _get_active_service_key(cfg, service)
        return jsonify({'value': val or ''})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/service-keys', methods=['POST'])
def add_service_key():
    try:
        data = request.get_json(force=True, silent=True) or {}
        service = str(data.get('service') or '')
        remark = str(data.get('remark') or '').strip() or '未命名'
        if service not in ('claude', 'codex'):
            return jsonify({'error': 'Invalid service'}), 400
        cfg = _load_unified_config()
        proxy = cfg.setdefault('proxy', {})
        bucket = proxy.setdefault(service, {})
        keys = bucket.setdefault('keys', [])
        # 生成
        kid = base64.urlsafe_b64encode(os.urandom(12)).decode('ascii').rstrip('=')
        rnd = base64.urlsafe_b64encode(os.urandom(24)).decode('ascii').rstrip('=')
        value = f"key_{rnd}"
        active = False if keys else True
        keys.append({'id': kid, 'value': value, 'remark': remark if keys else '默认', 'active': active, 'created_at': int(time.time())})
        _save_unified_config(cfg)
        return jsonify({'id': kid, 'value': value, 'active': active})
    except Exception as e:
        return jsonify({'error': str(e)}), 500






@app.route('/api/auth/service-keys/<key_id>', methods=['DELETE'])
def delete_service_key(key_id: str):
    try:
        service = request.args.get('service')
        if service not in ('claude', 'codex'):
            return jsonify({'error': 'Invalid service'}), 400
        cfg = _load_unified_config()
        bucket = (cfg.setdefault('proxy', {})).setdefault(service, {})
        keys = bucket.setdefault('keys', [])
        idx = None
        was_active = False
        for i, k in enumerate(list(keys)):
            if isinstance(k, dict) and k.get('id') == key_id:
                idx = i
                was_active = bool(k.get('active'))
                break
        if idx is None:
            return jsonify({'error': 'Not found'}), 404
        keys.pop(idx)
        if was_active:
            if keys:
                keys[0]['active'] = True
            else:
                bucket['auth_token'] = ''
                bucket['api_key'] = ''
        _save_unified_config(cfg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def ui_login():
    try:
        data = request.get_json(force=True, silent=True) or {}
        username = str(data.get('username') or '')
        password = str(data.get('password') or '')
        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400

        # 验证：优先文件（hash），否则环境变量（明文）
        auth = _get_ui_auth()
        ok = False
        if 'password_hash' in auth and 'salt' in auth:
            ok = (username == auth.get('username') and _verify_password(password, auth.get('salt'), auth.get('password_hash')))
        else:
            ok = (username == auth.get('username') and password == auth.get('password'))
        if not ok:
            return jsonify({'error': 'Invalid credentials'}), 401

        # 24小时有效
        now = int(time.time())
        payload = {"sub": username, "iat": now, "exp": now + 24 * 3600}
        token = _jwt_encode(payload, UI_JWT_SECRET)
        resp = make_response(jsonify({'token': token}))
        resp.set_cookie('ui_jwt', token, httponly=True, samesite='Lax')
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/ui-admin', methods=['GET'])
def get_ui_admin():
    try:
        auth = _get_ui_auth()
        # 不返回密码或 hash，仅返回用户名与是否持久化
        persisted = 'password_hash' in auth
        return jsonify({'username': auth.get('username'), 'persisted': persisted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/ui-admin', methods=['POST'])
def save_ui_admin():
    try:
        data = request.get_json(force=True, silent=True) or {}
        username = str(data.get('username') or '')
        password = str(data.get('password') or '')
        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400

        # 生成 salt 与 hash
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode('ascii')
        hash_b64 = _hash_password(password, salt)
        cfg = _load_unified_config()
        cfg['ui_admin'] = {'username': username, 'password_hash': hash_b64, 'salt': salt_b64}
        _save_unified_config(cfg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def ui_logout():
    try:
        resp = make_response(jsonify({'success': True}))
        resp.delete_cookie('ui_jwt')
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/keys', methods=['GET'])
def list_shared_keys():
    try:
        cfg = _load_unified_config()
        proxy = cfg.get('proxy') or {}
        shared = proxy.get('shared') or {}
        keys = [k for k in (shared.get('keys') or []) if isinstance(k, dict)]
        meta = []
        for k in keys:
            meta.append({
                'id': k.get('id'),
                'remark': k.get('remark'),
                'value': k.get('value') or '',
                'created_at': k.get('created_at')
            })
        return jsonify({'keys': meta})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/key', methods=['GET'])
def get_shared_key_value():
    try:
        key_id = request.args.get('id')
        cfg = _load_unified_config()
        shared = (cfg.get('proxy') or {}).get('shared') or {}
        keys = shared.get('keys') or []
        if key_id:
            for k in keys:
                if isinstance(k, dict) and k.get('id') == key_id:
                    return jsonify({'value': k.get('value') or ''})
            return jsonify({'error': 'Not found'}), 404
        # 无 id 返回 active
        val = _get_active_shared_key(cfg)
        return jsonify({'value': val or ''})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/keys', methods=['POST'])
def add_shared_key():
    try:
        data = request.get_json(force=True, silent=True) or {}
        remark = str(data.get('remark') or '').strip() or '未命名'
        cfg = _load_unified_config()
        proxy = cfg.setdefault('proxy', {})
        shared = proxy.setdefault('shared', {})
        keys = shared.setdefault('keys', [])
        # 生成
        kid = base64.urlsafe_b64encode(os.urandom(12)).decode('ascii').rstrip('=')
        rnd = base64.urlsafe_b64encode(os.urandom(24)).decode('ascii').rstrip('=')
        value = f"key_{rnd}"
        active = False if keys else True
        keys.append({'id': kid, 'value': value, 'remark': remark if keys else '默认', 'active': active, 'created_at': int(time.time())})
        _save_unified_config(cfg)
        return jsonify({'id': kid, 'value': value, 'active': active})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/keys/<key_id>', methods=['DELETE'])
def delete_shared_key(key_id: str):
    try:
        cfg = _load_unified_config()
        shared = (cfg.setdefault('proxy', {})).setdefault('shared', {})
        keys = shared.setdefault('keys', [])
        idx = None
        was_active = False
        for i, k in enumerate(list(keys)):
            if isinstance(k, dict) and k.get('id') == key_id:
                idx = i
                was_active = bool(k.get('active'))
                break
        if idx is None:
            return jsonify({'error': 'Not found'}), 404
        keys.pop(idx)
        # 若删除了 active，则将第一个设为 active
        if was_active and keys:
            keys[0]['active'] = True
        _save_unified_config(cfg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


def _apply_channel_renames(service: str, rename_map: Dict[str, str]) -> None:
    if not rename_map:
        return
    _rename_history_channels(service, rename_map)
    _rename_log_channels(service, rename_map)


def load_logs() -> list[Dict[str, Any]]:
    logs: list[Dict[str, Any]] = []
    log_path = LOG_FILE if LOG_FILE.exists() else (
        OLD_LOG_FILE if OLD_LOG_FILE.exists() else None
    )
    if log_path is None:
        return logs

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
    return logs


def load_history_usage() -> Dict[str, Dict[str, Dict[str, int]]]:
    if not HISTORY_FILE.exists():
        return {}
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}

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
    logs = load_logs()
    current_usage = aggregate_usage_from_logs(logs)
    history_usage = load_history_usage()
    combined_usage = combine_usage_maps(current_usage, history_usage)
    return {
        'logs': logs,
        'current_usage': current_usage,
        'history_usage': history_usage,
        'combined_usage': combined_usage
    }

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
        
        usage_snapshot = build_usage_snapshot()
        logs = usage_snapshot['logs']
        request_count = len(logs)
        combined_usage = usage_snapshot['combined_usage']

        service_usage_totals: Dict[str, Dict[str, int]] = {}
        for service_name, channels in combined_usage.items():
            service_usage_totals[service_name] = compute_total_metrics(channels)

        for expected_service in ('claude', 'codex'):
            service_usage_totals.setdefault(expected_service, empty_metrics())

        overall_totals = empty_metrics()
        for totals in service_usage_totals.values():
            merge_usage_metrics(overall_totals, totals)

        usage_summary = {
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
            'usage_summary': usage_summary
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
        history_usage = load_history_usage()
        for service in history_usage:
            for channel in history_usage[service]:
                for key in history_usage[service][channel]:
                    history_usage[service][channel][key] = 0
        save_history_usage(history_usage)

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

def start_ui_server(port=3300):
    """启动UI服务器并打开浏览器"""
    print(f"启动Web UI服务器在端口 {port}")

    # 启动Flask应用
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    start_ui_server()
