# 使用官方Python运行时作为基础镜像
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN echo "deb http://deb.debian.org/debian trixie main" > /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian-security trixie-security main" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY pyproject.toml ./
COPY src/ ./src/

# 安装Python依赖
RUN pip install -e .

# 创建必要的目录
RUN mkdir -p /root/.clp/run /root/.clp/data

# 暴露端口
# 3210: Claude代理服务端口
# 3211: Codex代理服务端口
# 3300: Web UI界面端口
EXPOSE 3210 3211 3300

# 容器启动命令 - 使用新的Server模式
CMD ["python", "-m", "src.main", "server"]

# 添加健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3300/ || exit 1
