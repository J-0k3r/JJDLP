# 使用Python 3.9官方镜像
#dlp服务
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 清空所有默认 APT 源（包括 sources.list 和 sources.list.d/）
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true

# 使用清华镜像源（支持 trixie）
RUN echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie main" > /etc/apt/sources.list && \
    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie-updates main" >> /etc/apt/sources.list && \
    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian-security trixie-security main" >> /etc/apt/sources.list

# 安装系统依赖（PDF导出需要）
RUN apt-get update && apt-get install -y \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制应用代码
COPY . .

# 创建必要的目录
RUN mkdir -p uploads logs static/css static/js static/images instance

# 设置权限
RUN chmod +x run.py

# 暴露端口
EXPOSE 5000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# 启动命令
CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "5000"]
