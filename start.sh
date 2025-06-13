#!/bin/bash

# 检查并关闭占用端口的进程
check_and_kill_port() {
    local port=$1
    local pid=$(lsof -ti :$port)
    if [ ! -z "$pid" ]; then
        echo "Killing process using port $port (PID: $pid)"
        kill -9 $pid
        sleep 1
    fi
}

# 清理端口
check_and_kill_port 8000
check_and_kill_port 3000

# 激活conda环境
source /Users/lizi/miniconda3/bin/activate python39

# 启动后端服务
echo "Starting backend service..."
cd web-backend
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# 启动前端服务
echo "Starting frontend service..."
cd ../web-frontend
npm install
npm run dev &
FRONTEND_PID=$!

# 等待用户中断
echo "Services started. Press Ctrl+C to stop."
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" INT
wait 