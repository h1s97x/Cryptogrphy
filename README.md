# 密码学平台 - Fluent UI

现代化的密码学算法学习与实验平台，采用 Fluent Design 设计语言。

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![PyQt5](https://img.shields.io/badge/PyQt5-5.15+-green.svg)](https://www.riverbankcomputing.com/software/pyqt/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## ✨ 特性

- 🎨 **现代化界面** - 采用 Fluent Design 设计语言
- 🌓 **主题支持** - 深色/浅色主题自动切换
- 📚 **丰富算法** - 28个密码学算法完整实现
- 🔐 **全面覆盖** - 经典密码、对称密码、公钥密码、哈希算法、数学基础
- 📊 **实时反馈** - 操作日志和中间值显示
- 💾 **文件操作** - 支持文件导入/导出
- 📋 **剪贴板** - 一键复制加密结果
- ⚡ **异步处理** - 耗时操作不阻塞界面

## 🚀 快速开始

### 环境要求

- Python 3.8 或更高版本
- Windows / macOS / Linux

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

## 📚 支持的算法 (28/37)

### 经典密码 (7/7) ✅
- ✅ Hill 密码 - 矩阵加密
- ✅ Caesar 密码 - 移位加密
- ✅ Vigenere 密码 - 多表替换
- ✅ Playfair 密码 - 双字母替换
- ✅ Enigma 密码 - 转子密码机
- ✅ Monoalphabetic 密码 - 单表替换
- ✅ Frequency Analysis - 频率分析

### 对称密码 (8/10)
- ✅ AES - 高级加密标准
- ✅ DES - 数据加密标准
- ✅ SM4 - 国密分组密码
- ✅ RC4 - 流密码
- ✅ SPECK - NSA轻量级密码
- ✅ SIMON - NSA轻量级密码
- ✅ Block Mode - ECB/CBC模式
- 🚧 SEAL - 流密码
- 🚧 ZUC - 祖冲之算法
- 🚧 Crypto-1 - RFID加密

### 公钥密码 (4/7)
- ✅ RSA - 公钥加密
- ✅ RSA Sign - RSA数字签名
- ✅ ElGamal - 公钥加密
- ✅ ECDSA - 椭圆曲线数字签名
- 🚧 ECC - 椭圆曲线加密
- 🚧 SM2 - 国密公钥密码
- 🚧 SM2 Sign - 国密数字签名

### 哈希算法 (7/8)
- ✅ MD5 - 消息摘要算法
- ✅ SHA-1 - 安全哈希算法
- ✅ SHA-256 - SHA-2系列
- ✅ SHA-3 - 最新哈希标准
- ✅ SM3 - 国密哈希算法
- ✅ HMAC-MD5 - 消息认证码
- ✅ AES-CBC-MAC - 分组密码MAC
- 🚧 Hash Reverse - 哈希反查

### 数学基础 (3/3) ✅
- ✅ Euler 定理 - 欧拉函数
- ✅ CRT - 中国剩余定理
- ✅ Euclidean - 欧几里得算法

**完成度**: 28/37 (75.7%)

✅ 已完成 | 🚧 开发中

## 📁 项目结构

```
Cryptography/
├── core/                      # 核心算法实现
│   ├── algorithms/           # 算法模块
│   │   ├── classical/       # 经典密码 (7个)
│   │   ├── symmetric/       # 对称密码 (10个)
│   │   ├── asymmetric/      # 非对称密码 (7个)
│   │   ├── hash/            # 哈希算法 (8个)
│   │   └── mathematical/    # 数学基础 (3个)
│   ├── interfaces/          # 接口定义
│   └── validators/          # 验证器
├── ui/                       # 用户界面
│   └── fluent/              # Fluent UI实现
│       ├── main_window.py   # 主窗口
│       ├── components/      # 可复用组件
│       │   └── algorithm_card.py  # 算法卡片组件
│       ├── interfaces/      # 界面页面
│       │   ├── home_interface.py  # 首页
│       │   └── settings_interface.py  # 设置页
│       └── widgets/         # 算法界面 (28个)
├── infrastructure/          # 基础设施
│   ├── converters/         # 类型转换工具
│   ├── security/           # 安全工具
│   └── Path.py             # 路径工具
├── CryptographicProtocol/  # 密码协议
├── resources/              # 资源文件
├── docs/                   # 文档
│   ├── guides/            # 使用指南
│   ├── phases/            # 开发阶段文档
│   └── DEVELOPMENT_PROGRESS.md  # 开发进度
├── test_algorithms.py      # 自动化测试脚本
├── main.py                 # 程序入口
└── requirements.txt        # 依赖列表
```

## 🧪 测试

运行自动化测试脚本：

```bash
python test_algorithms.py
```

测试内容包括：
- ✅ 所有Widget导入测试
- ✅ 核心算法可用性测试
- ✅ 主窗口创建测试

## 📖 文档

- [开发进度](docs/DEVELOPMENT_PROGRESS.md) - 详细的开发进度和算法列表
- [UI 使用指南](docs/UI_GUIDE.md) - 界面使用说明
- [快速开始](docs/guides/QUICK_START.md) - 快速上手指南
- [开发指南](docs/guides/DEVELOPMENT_GUIDE.md) - 开发者文档
- [QFluentWidgets 快速入门](docs/guides/QFLUENTWIDGETS_QUICK_START.md) - UI框架文档
- [架构说明](docs/ARCHITECTURE.md) - 系统架构设计

## 🔄 版本历史

### v2.0 - Fluent UI (当前版本)
- 全新 Fluent Design 界面
- 28个算法完整实现
- 深色/浅色主题支持
- 现代化卡片式布局
- 实时日志和操作反馈

### v1.0 - Classic UI
- 经典界面设计
- 37个算法原型实现
- 基础功能完整

如需使用经典 UI 版本，请切换到 `classic-ui` 分支：

```bash
git checkout classic-ui
python main.py
```

## 🛠️ 技术栈

- **Python** 3.8+ - 核心语言
- **PyQt5** - GUI框架
- **QFluentWidgets** - Fluent Design组件库
- **NumPy** - 数值计算
- **PyCryptodome** - 密码学库
- **gmpy2** - 大数运算

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

### 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'feat: Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 提交规范

- `feat`: 新功能
- `fix`: 修复bug
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建/工具相关

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 👥 作者

密码学平台开发团队

## 🙏 致谢

- [QFluentWidgets](https://qfluentwidgets.com/) - 优秀的 Fluent Design 组件库
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) - 强大的 Python GUI 框架
- [PyCryptodome](https://www.pycryptodome.org/) - 密码学算法库

---

⭐ 如果这个项目对你有帮助，请给我们一个 Star！
