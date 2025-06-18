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

# 检查conda环境是否存在
if ! conda env list | grep -q "penrecon"; then
    echo "Error: conda environment 'penrecon' not found!"
    echo "Please create the environment first:"
    echo "conda create -n penrecon python=3.9 -y"
    exit 1
fi

# 激活conda环境
echo "Activating conda environment 'penrecon'..."
source ~/miniconda3/bin/activate penrecon

# 检查环境是否激活成功
if [ "$CONDA_DEFAULT_ENV" != "penrecon" ]; then
    echo "Error: Failed to activate conda environment!"
    exit 1
fi

echo "Conda environment activated: $CONDA_DEFAULT_ENV"

# 启动后端服务
echo "Starting backend service..."
cd web-backend
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# 等待后端启动
sleep 3

# 启动前端服务
echo "Starting frontend service..."
cd ../web-frontend
npm install
npm run dev &
FRONTEND_PID=$!

# 等待用户中断
echo "Services started successfully!"
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo "Press Ctrl+C to stop."
trap "echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Services stopped.'" INT
wait 