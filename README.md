# 密码学平台 - Fluent UI

现代化的密码学算法学习与实验平台，采用 Fluent Design 设计语言。

## 特性

- 🎨 现代化 Fluent Design UI
- 🌓 深色/浅色主题支持
- 📚 多种密码学算法实现
- 🔐 经典密码、分组密码、公钥密码、哈希算法
- 📊 实时日志和操作反馈
- 💾 文件导入/导出功能

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 运行程序

```bash
# 自动主题（跟随系统）
python main.py

# 浅色主题
python main.py --theme light

# 深色主题
python main.py --theme dark
```

## 支持的算法

### 经典密码
- Hill 密码 ✅
- Caesar 密码 ✅
- Vigenere 密码 🚧

### 分组密码
- AES ✅
- DES 🚧

### 公钥密码
- RSA ✅

### 哈希算法
- SHA-256 ✅

### 数学基础
- Euler 函数 🚧

✅ 已完成 | 🚧 开发中

## 项目结构

```
.
├── core/                   # 核心算法实现
│   ├── algorithms/        # 算法模块
│   │   ├── classical/    # 经典密码
│   │   ├── symmetric/    # 对称密码
│   │   ├── asymmetric/   # 非对称密码
│   │   ├── hash/         # 哈希算法
│   │   └── mathematical/ # 数学基础
│   ├── interfaces/       # 接口定义
│   └── validators/       # 验证器
├── ui/                    # 用户界面
│   └── fluent/           # Fluent UI
│       ├── main_window.py      # 主窗口
│       ├── components/         # 可复用组件
│       ├── interfaces/         # 界面页面
│       └── widgets/            # 算法界面
├── infrastructure/        # 基础设施
│   ├── converters/       # 类型转换
│   ├── security/         # 安全工具
│   └── Path.py           # 路径工具
├── CryptographicProtocol/ # 密码协议
├── resources/            # 资源文件
├── docs/                 # 文档
└── main.py              # 程序入口

```

## 开发指南

详见 [开发文档](docs/guides/DEVELOPMENT_GUIDE.md)

## 文档

- [UI 使用指南](docs/UI_GUIDE.md)
- [快速开始](docs/guides/QUICK_START.md)
- [QFluentWidgets 快速入门](docs/guides/QFLUENTWIDGETS_QUICK_START.md)
- [架构说明](docs/ARCHITECTURE.md)

## 旧版本

如需使用经典 UI 版本，请切换到 `classic-ui` 分支：

```bash
git checkout classic-ui
python main.py
```

## 技术栈

- Python 3.8+
- PyQt5
- QFluentWidgets
- NumPy
- PyCryptodome

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
