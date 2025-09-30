# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在本代码仓库中工作时提供指导。

## ⚠️ 重要提示

**请使用简体中文与我沟通！** 所有回复、说明、错误信息等都应使用简体中文。

## 项目概述

CLP (CLI Proxy) 是一个本地AI代理工具，用于管理和转发 Claude 和 Codex 服务的API请求。它提供统一的CLI管理、Web UI监控、多配置支持、请求过滤、负载均衡和模型路由功能。

## 核心架构

### 服务结构
- **BaseProxyService** (`src/core/base_proxy.py`): 提供核心代理功能的抽象基类
  - 使用 httpx 处理异步 HTTP 代理
  - 实现流式响应支持
  - 管理请求过滤和日志记录
  - 提供模型路由和负载均衡
  - 跟踪使用统计
  - 通过 RealTimeRequestHub 支持 WebSocket 实时请求监控

- **ClaudeProxy** (`src/claude/proxy.py`): Claude 服务实现（端口 3210）
- **CodexProxy** (`src/codex/proxy.py`): Codex 服务实现（端口 3211）

### 配置管理
- **ConfigManager** (`src/config/config_manager.py`): 基础配置管理器
  - 从 `~/.clp/{service}.json` 加载配置
  - 支持每个服务的多个命名配置
  - 使用 `active` 标志跟踪激活配置
  - 支持基于权重的负载均衡

- **CachedConfigManager** (`src/config/cached_config_manager.py`): 添加基于文件签名的缓存以减少 I/O

配置文件格式：
```json
{
  "config_name": {
    "base_url": "https://api.example.com",
    "auth_token": "token_here",
    "api_key": "key_here",
    "weight": 10,
    "active": true
  }
}
```

### 模型路由
模型路由配置文件 `~/.clp/data/model_router_config.json` 支持：
- **model-mapping 模式**：将模型名称或配置映射到不同的目标模型
- **config-mapping 模式**：将特定模型路由到不同的配置
- 通过文件签名检查自动重新加载配置变更

### 负载均衡
负载均衡配置文件 `~/.clp/data/lb_config.json`：
- **active-first 模式**：始终使用激活配置
- **weight-based 模式**：按权重选择，跟踪失败，排除不健康配置
- 每个服务的失败阈值跟踪
- 自动排除重复失败的配置

### 请求过滤
- **RequestFilter** (`src/filter/request_filter.py`): 从 `~/.clp/filter.json` 应用文本替换规则
- **CachedRequestFilter** (`src/filter/cached_request_filter.py`): 添加文件签名缓存
- 过滤器支持对请求体的 `replace` 和 `remove` 操作

### 服务控制
- **BaseServiceController** (`src/core/base_proxy.py:820`): 用于启动/停止服务的基础控制器
- **Claude/Codex 控制器** (`src/claude/ctl.py`, `src/codex/ctl.py`): 服务特定控制器

## 开发命令

### 环境变量配置

项目支持通过环境变量控制服务监听地址：

- `CLP_UI_HOST` - UI 服务监听地址（默认 `0.0.0.0`）
- `CLP_PROXY_HOST` - Claude/Codex 代理服务监听地址（默认 `0.0.0.0`）

**使用示例**：

```bash
# 本地开发环境 - 允许所有网络接口访问
clp start

# 公网服务器部署 - 仅本地访问（安全）
export CLP_UI_HOST=127.0.0.1
export CLP_PROXY_HOST=127.0.0.1
clp restart

# 或者一次性设置
CLP_UI_HOST=127.0.0.1 CLP_PROXY_HOST=127.0.0.1 clp start

# 持久化配置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export CLP_UI_HOST=127.0.0.1' >> ~/.bashrc
echo 'export CLP_PROXY_HOST=127.0.0.1' >> ~/.bashrc
source ~/.bashrc
```

### 安装
```bash
# 从源代码安装
pip install -e .

# 从 wheel 包安装
pip install --user --force-reinstall ./dist/clp-1.9.0-py3-none-any.whl
```

### 构建
```bash
# 构建 wheel 包
python -m build
```

### 服务管理
```bash
# 启动所有服务 (claude:3210, codex:3211, ui:3300)
clp start

# 停止所有服务
clp stop

# 重启所有服务
clp restart

# 查看服务状态
clp status

# 打开 Web UI
clp ui
```

### 配置管理
```bash
# 列出配置
clp list claude
clp list codex

# 切换激活配置（无需重启 - 动态重载）
clp active claude prod
clp active codex dev
```

### 强制停止端口（如需要）
```bash
# macOS/Linux
lsof -ti:3210,3211,3300 | xargs kill -9
```

## 重要文件

- `~/.clp/claude.json` - Claude 配置文件
- `~/.clp/codex.json` - Codex 配置文件
- `~/.clp/filter.json` - 请求过滤规则
- `~/.clp/data/model_router_config.json` - 模型路由配置
- `~/.clp/data/lb_config.json` - 负载均衡配置
- `~/.clp/data/proxy_requests.jsonl` - 请求日志（最近 100 条记录）
- `~/.clp/run/*.pid` - 服务 PID 文件
- `~/.clp/run/*.log` - 服务日志文件

## 核心特性

1. **动态配置切换**：无需重启 CLI 终端即可切换配置（保留上下文）
2. **请求过滤**：从请求中过滤敏感数据
3. **模型路由**：根据规则将请求路由到不同的模型或配置
4. **负载均衡**：使用基于权重或优先激活的策略在多个配置间分配请求
5. **实时监控**：WebSocket 端点 `/ws/realtime` 用于实时请求跟踪
6. **使用统计**：自动解析和记录 token 使用情况

## API 端点测试

ClaudeProxy 和 CodexProxy 都实现了 `test_endpoint()` 方法用于连接性测试。该测试发送一个最小请求来验证 API 是否可访问。

## 技术说明

- 服务通过 `platform_helper.create_detached_process()` 作为独立进程运行
- 所有服务使用 FastAPI + uvicorn，采用 h11 HTTP 实现
- 异步操作使用 httpx.AsyncClient 并启用 keep-alive
- 日志轮转：保留最近 100 条请求记录
- 配置变更通过文件签名（mtime + size）检测