# PenRecon - 渗透测试辅助工具

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/React-18+-green.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-red.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 项目简介

PenRecon 是一个基于 AutoRecon 的渗透测试辅助工具，提供了简单的 Web 界面来管理扫描任务和查看结果。该项目集成了 AutoRecon 工具链，并尝试通过 AI 分析来辅助理解扫描结果。

### 🎯 主要功能

- 🔍 **扫描管理**: 集成 AutoRecon 工具链，支持基本的网络侦察
- 🤖 **AI 辅助**: 尝试使用 AI 分析扫描结果并提供建议
- 📊 **结果展示**: 简单的网络拓扑图显示扫描结果
- 📁 **文件处理**: 支持压缩文件上传和结果查看
- 📝 **日志显示**: 显示扫描进度和基本日志信息
- 🖥️ **Web界面**: 提供基本的 Web 操作界面

### 🏗️ 技术架构

```
PenRecon/
├── web-backend/          # FastAPI 后端服务
│   ├── app.py           # 主应用文件
│   ├── requirements.txt # Python 依赖
│   └── results/         # 扫描结果存储
├── web-frontend/        # React 前端应用
│   ├── src/
│   │   ├── App.jsx      # 主组件
│   │   └── App.css      # 样式文件
│   └── package.json     # Node.js 依赖
└── README.md           # 项目文档
```

## 🚀 快速开始

### 系统要求

- **操作系统**: Linux (推荐 Ubuntu 20.04+)
- **Python**: 3.9+ (推荐使用 conda 环境)
- **Node.js**: 16+ (用于前端开发)
- **内存**: 建议 4GB RAM 以上
- **存储**: 建议 10GB 可用空间以上

### 1. 环境准备

#### 安装 Miniconda (推荐)

```bash
# 下载并安装 Miniconda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh

# 重新加载 shell 配置
source ~/.bashrc
```

#### 安装 AutoRecon

```bash
# 安装 AutoRecon 及其依赖
sudo apt update
sudo apt install -y python3-pip git

# 克隆 AutoRecon 仓库
git clone https://github.com/Tib3rius/AutoRecon.git
cd AutoRecon

# 安装 AutoRecon
pip3 install -r requirements.txt
sudo python3 setup.py install

# 验证安装
autorecon --help
```

### 2. 项目安装

```bash
# 克隆项目
git clone <repository-url>
cd PenRecon

# 创建 Python 虚拟环境
conda create -n penrecon python=3.9 -y
conda activate penrecon

# 安装后端依赖
cd web-backend
pip install -r requirements.txt

# 安装前端依赖
cd ../web-frontend
npm install
```

### 3. 配置环境变量

创建 `.env` 文件在 `web-backend` 目录下：

```bash
# AI 分析配置 (可选)
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# 其他配置
LOG_LEVEL=INFO
MAX_SCAN_DURATION=3600
```

### 4. 启动服务

#### 启动后端服务

```bash
cd web-backend
conda activate penrecon
python app.py
```

后端服务将在 `http://localhost:8000` 启动。

#### 启动前端服务 (开发模式)

```bash
cd web-frontend
npm start
```

前端应用将在 `http://localhost:3000` 启动。

#### 生产环境部署

```bash
# 构建前端
cd web-frontend
npm run build

# 使用 nginx 或其他 Web 服务器部署
```

## 📖 使用说明

### 基本操作流程

1. **启动扫描**
   - 在侧边栏输入目标 IP 地址
   - 点击 "开始扫描" 按钮
   - 系统会检查是否已有扫描结果

2. **查看扫描进度**
   - 查看扫描日志
   - 观察扫描状态
   - 等待扫描完成

3. **查看结果**
   - 扫描完成后显示网络拓扑图
   - 查看发现的开放端口和服务
   - 浏览基本信息

4. **AI 分析**
   - 系统尝试生成 AI 分析报告
   - 查看分析建议
   - 获取基本指导

### 其他功能

#### 文件上传

支持上传压缩的 AutoRecon 结果文件：

- **支持格式**: ZIP, TAR.GZ
- **文件结构**: 解压后应包含 AutoRecon 标准输出格式
- **使用方法**: 选择文件 → 点击上传 → 查看结果

#### 结果管理

- **覆盖扫描**: 选择是否覆盖现有结果
- **结果清理**: 清理旧的扫描状态
- **数据存储**: 扫描结果保存在 `results/` 目录

## 🔧 API 接口

### 主要端点

| 端点 | 方法 | 描述 |
|------|------|------|
| `/ping` | GET | 健康检查 |
| `/scan` | POST | 启动新扫描 |
| `/scan_status/{scan_id}` | GET | 获取扫描状态 |
| `/scan_results/{scan_id}` | GET | 获取扫描结果 |
| `/check_results_exists/{ip}` | GET | 检查结果是否存在 |
| `/load_existing_results/{ip}` | GET | 加载现有结果 |
| `/analyze_scan_results/{ip}` | GET | AI 分析扫描结果 |
| `/upload_compressed_results` | POST | 上传压缩结果 |

### 请求示例

#### 启动扫描

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1", "overwrite": false}'
```

#### 获取扫描状态

```bash
curl -X GET "http://localhost:8000/scan_status/{scan_id}"
```

## 🛠️ 开发说明

### 项目结构

```
PenRecon/
├── web-backend/
│   ├── app.py                 # FastAPI 主应用
│   ├── requirements.txt       # Python 依赖
│   ├── results/              # 扫描结果目录
│   └── temp_compressed/      # 临时文件目录
├── web-frontend/
│   ├── src/
│   │   ├── App.jsx           # React 主组件
│   │   ├── App.css           # 样式文件
│   │   └── index.js          # 应用入口
│   ├── public/               # 静态资源
│   └── package.json          # 项目配置
└── docs/                     # 文档目录
```

### 开发环境设置

```bash
# 后端开发
cd web-backend
conda activate penrecon
python app.py

# 前端开发
cd web-frontend
npm start
```

### 代码规范

- **Python**: 遵循 PEP 8 规范
- **JavaScript**: 使用 ESLint 和 Prettier
- **注释**: 添加必要的文档字符串
- **测试**: 建议编写基本测试

## 🔍 常见问题

### 问题排查

#### 1. Python 环境问题

```bash
# 如果遇到 pydantic-core 编译错误
conda create -n penrecon python=3.9 -y
conda activate penrecon
pip install -r requirements.txt
```

#### 2. AutoRecon 安装问题

```bash
# 确保系统依赖已安装
sudo apt update
sudo apt install -y python3-pip git nmap

# 重新安装 AutoRecon
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

#### 3. 端口占用问题

```bash
# 检查端口占用
sudo netstat -tulpn | grep :8000
sudo netstat -tulpn | grep :3000

# 杀死占用进程
sudo kill -9 <PID>
```

#### 4. 权限问题

```bash
# 确保有足够权限运行扫描
sudo chmod +x /usr/bin/nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

### 日志查看

```bash
# 查看后端日志
tail -f web-backend/logs/app.log

# 查看系统日志
sudo journalctl -u penrecon -f
```

## 🤝 参与贡献

### 如何贡献

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

### 开发建议

- 遵循现有的代码风格
- 添加必要的测试
- 更新相关文档
- 确保基本功能正常

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [AutoRecon](https://github.com/Tib3rius/AutoRecon) - 自动化网络侦察工具
- [FastAPI](https://fastapi.tiangolo.com/) - Python Web 框架
- [React](https://reactjs.org/) - JavaScript UI 库
- [DeepSeek](https://www.deepseek.com/) - AI 分析服务

## 📞 联系方式

- **项目维护者**: PenRecon Team
- **邮箱**: support@penrecon.com
- **项目主页**: https://github.com/penrecon/penrecon
- **问题反馈**: https://github.com/penrecon/penrecon/issues

---

**重要提醒**: 本工具仅用于授权的渗透测试和安全研究。使用者需要确保在合法和授权的环境中使用，并承担相应的法律责任。
