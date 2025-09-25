FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install project
COPY pyproject.toml README.md /app/
COPY src /app/src
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ARG INSTALL_EDITABLE=false

RUN pip install --no-cache-dir --upgrade pip && \
    if [ "$INSTALL_EDITABLE" = "true" ]; then pip install --no-cache-dir -e .; else pip install --no-cache-dir .; fi && \
    chmod +x /usr/local/bin/entrypoint.sh

# Expose service ports
EXPOSE 3210 3211 3300

# Persist configs and runtime files
VOLUME ["/root/.clp"]

# 默认通过 entrypoint 启动、捕获信号并优雅退出
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["start"]
LABEL org.opencontainers.image.title="CLP" \
      org.opencontainers.image.description="Local CLI proxy for Claude/Codex" \
      org.opencontainers.image.licenses="MIT"

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD /bin/sh -lc '[ -f /root/.clp/run/claude_proxy.pid ] && [ -f /root/.clp/run/codex_proxy.pid ]'
