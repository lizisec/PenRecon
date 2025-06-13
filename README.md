# AutoRecon 可视化分析工具

这是一个基于 [AutoRecon](https://github.com/Tib3rius/AutoRecon) 的二次开发项目，旨在提供更直观的扫描结果分析和可视化界面。本工具使用 Vue 3 + TypeScript + FastAPI 构建，将 AutoRecon 的扫描结果转化为交互式的网络拓扑图和 AI 辅助分析报告。

## 主要特点

- 🎯 完全兼容 AutoRecon 的扫描结果格式
- 📊 交互式网络拓扑图展示
  - 主机、端口和服务之间的关系可视化
  - 支持节点展开/折叠
  - 支持缩放和拖拽
- 🤖 DeepSeek AI 辅助分析
  - 自动分析扫描结果
  - 生成安全评估报告
  - 识别潜在漏洞和攻击路径
- 🎨 现代化用户界面
  - 响应式设计
  - 实时分析状态更新
  - 支持暗色/亮色主题

## 系统要求

- Python 3.9+
- Node.js 16+
- Conda 环境
- AutoRecon 已安装并可用

## 快速开始

1. 克隆项目
```bash
git clone [your-repo-url]
cd [your-repo-name]
```

2. 安装后端依赖
```bash
cd web-backend
conda create -n python3.9 python=3.9
conda activate python3.9
pip install -r requirements.txt
```

3. 安装前端依赖
```bash
cd web-frontend
npm install
```

4. 配置环境变量
在 `web-backend` 目录下创建 `.env` 文件：
```env
DEEPSEEK_API_KEY=your_api_key_here
UPLOAD_DIR=uploads
```

5. 启动服务
```bash
# 使用启动脚本（推荐）
./start.sh

# 或分别启动
# 后端
cd web-backend
conda activate python3.9
python main.py

# 前端
cd web-frontend
npm run dev
```

## 使用指南

1. 使用 AutoRecon 进行扫描
```bash
autorecon [target-ip]
```

2. 打开浏览器访问 http://localhost:3000

3. 上传 AutoRecon 扫描结果
   - 支持拖拽上传
   - 支持选择目录上传
   - 自动解析扫描结果

4. 查看分析结果
   - 网络拓扑图展示主机和服务关系
   - AI 分析报告提供安全评估
   - 支持导出分析报告

## 项目结构

```
.
├── web-backend/          # 后端服务
│   ├── main.py          # FastAPI 主程序
│   ├── autorecon_analyzer.py  # 分析器
│   └── requirements.txt  # Python 依赖
├── web-frontend/        # 前端界面
│   ├── src/            # 源代码
│   └── package.json    # 前端依赖
└── start.sh            # 启动脚本
```

## 常见问题

1. **Q: 为什么需要 DeepSeek API 密钥？**  
   A: 用于 AI 辅助分析功能，提供更深入的安全评估。

2. **Q: 支持哪些 AutoRecon 版本？**  
   A: 支持 AutoRecon 最新版本，建议使用最新版获取最佳体验。

3. **Q: 如何处理大型扫描结果？**  
   A: 系统会自动优化大型结果的处理，但建议控制单次扫描的目标范围。

## 注意事项

- 确保 AutoRecon 已正确安装并可用
- 建议使用现代浏览器（Chrome、Firefox、Safari 等）
- 保持 Python 和 Node.js 环境更新
- 定期更新依赖包以获取新特性和安全修复

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目。在提交 PR 前，请确保：

1. 代码符合项目规范
2. 添加必要的测试
3. 更新相关文档

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 致谢

- [AutoRecon](https://github.com/Tib3rius/AutoRecon) - 基础扫描工具
- [DeepSeek](https://deepseek.com) - AI 分析支持
- 所有项目贡献者
