#!/bin/sh

# 优雅退出：捕获 SIGTERM/SIGINT 并在退出时调用 clp stop
_shutdown() {
  echo "[clp] stopping services..."
  clp stop >/dev/null 2>&1 || true
  exit 0
}
trap _shutdown TERM INT

# 目录初始化（避免因为目录不存在导致启动失败且无日志）
mkdir -p /root/.clp/run /root/.clp/data || true

echo "[clp] starting services..."
echo "[clp] NOTE: 首次运行为占位模式，请在 /root/.clp 下编辑配置后重启容器。"
if [ "${DEBUG_STARTUP}" = "true" ]; then
  set -x
  echo "[clp] debug: whoami=$(whoami) pwd=$(pwd) python=$(command -v python)"
  python -V || true
  echo "[clp] debug: sys.path" && python - <<'PY'
import sys
print("\n".join(sys.path))
PY
fi

# 是否启动 UI: 通过环境变量 ENABLE_UI=true 控制
if [ "${ENABLE_UI}" = "true" ]; then
  echo "[clp] enabling Web UI on port 3300"
  (python -m src.main ui >/dev/null 2>&1 &)
fi

# 启动服务；如失败，仅提示并继续保活，避免容器重启风暴
if ! python -m src.main start; then
  echo "[clp] WARN: python -m src.main start failed, fallback to clp start"
  if ! clp start; then
    echo "[clp] ERROR: both 'python -m src.main start' and 'clp start' failed. 请检查 /root/.clp 配置与日志文件。" >&2
  fi
fi

# 将现有日志输出到 STDOUT，便于 docker logs 查看
for f in /root/.clp/run/*.log; do
  [ -f "$f" ] && tail -n +1 -F "$f" &
done

# 保持前台常驻以接收信号
while :; do sleep 3600; done
