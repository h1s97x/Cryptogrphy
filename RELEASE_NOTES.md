# Release Notes - v2.2.0

## 🎉 密码学平台 v2.2.0 发布

这是一个重大更新版本，完成了所有密码协议的 Fluent UI 重构，并提供了完整的可执行应用。

---

## ✨ 新增功能

### 密码协议重构完成（7个协议）

全部采用现代化 Fluent Design 界面：

1. **Replay Attack** - 重放攻击演示
   - ECDSA 签名验证
   - 攻击者截获和重放演示
   - 4个功能卡片

2. **Verify** - 挑战-响应验证协议
   - AES-ECB 加密验证
   - PC 与智能卡模拟
   - 6个功能卡片

3. **Millionaire** - 百万富翁问题
   - 安全多方计算演示
   - RSA 加密比较
   - 5个功能卡片

4. **Zero Knowledge Proof** - 零知识证明
   - 阿里巴巴洞穴问题
   - 单次和批量验证
   - 统计分析
   - 5个功能卡片

5. **Digital Envelope** - 数字信封
   - RSA + AES 混合加密
   - 2048位 RSA + 128位 AES
   - 4个功能卡片

6. **Diffie-Hellman** - DH 密钥交换
   - 离散对数密钥协商
   - 支持 4-32 字节密钥
   - 5个功能卡片

7. **Digital Certificate** - 数字证书
   - PKI 公钥基础设施
   - X.509 证书生成和验证
   - 5个功能卡片

### 应用打包

- 提供 Windows 可执行文件
- 无需 Python 环境
- 一键安装使用
- 包含所有资源和依赖

---

## 🔧 改进优化

### 项目结构优化

- 删除旧协议目录 `CryptographicProtocol/`
- 整理测试文件到 `tests/protocols/`
- 清理过时文档（删除 11 个文档，5 个目录）
- 根目录更加整洁

### 文档完善

- 添加打包指南 `docs/BUILD_GUIDE.md`
- 添加用户手册 `USER_GUIDE.md`
- 添加快速开始 `QUICK_BUILD.md`
- 完善协议重构文档

### 性能优化

- 使用异步线程处理耗时操作
- 优化密钥生成速度
- 改进界面响应性

---

## 📦 下载说明

### 可执行应用（推荐）

下载 `密码学平台.zip`（约 80-120 MB）

**使用方法**:
1. 解压到任意目录
2. 双击 `密码学平台.exe`
3. 开始使用

**系统要求**:
- Windows 10/11 (64位)
- 无需 Python 环境
- 无需安装依赖

### 源代码

如需从源码运行：

```bash
# 克隆仓库
git clone https://github.com/h1s97x/PyCryptoLab.git
cd PyCryptoLab

# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py
```

---

## 📊 统计数据

### 功能统计

- **算法总数**: 35 个
  - 经典密码: 7 个
  - 对称密码: 7 个
  - 公钥密码: 4 个
  - 哈希算法: 7 个
  - 数学基础: 3 个
  - 密码协议: 7 个

### 代码统计

- 新增代码: 约 3500+ 行
- 删除代码: 约 10000+ 行（清理）
- 净减少: 约 6500 行
- 提交次数: 15+ 次

### 文档统计

- 新增文档: 8 个
- 删除文档: 11 个
- 更新文档: 5 个

---

## 🐛 已知问题

### 首次启动慢

- **现象**: 首次启动需要 10-20 秒
- **原因**: 需要加载所有模块
- **解决**: 属于正常现象，后续启动会更快

### 杀毒软件误报

- **现象**: 可能被杀毒软件拦截
- **原因**: PyInstaller 打包程序的常见问题
- **解决**: 添加到白名单，程序是安全的

---

## 🔄 升级说明

### 从 v2.1.0 升级

- 直接下载新版本即可
- 无需卸载旧版本
- 配置和数据不会丢失

### 从更早版本升级

- 建议全新安装
- 界面和功能有较大变化

---

## 📝 完整更新日志

查看 `CHANGELOG.md` 获取详细的更新历史。

---

## 🙏 致谢

感谢所有贡献者和用户的支持！

特别感谢：
- QFluentWidgets 提供的优秀 UI 框架
- cryptography 和 pycryptodome 提供的密码学库
- 所有提出建议和反馈的用户

---

## 📞 联系方式

- **GitHub**: https://github.com/h1s97x/PyCryptoLab
- **Issues**: https://github.com/h1s97x/PyCryptoLab/issues
- **Discussions**: https://github.com/h1s97x/PyCryptoLab/discussions

---

## 📄 许可证

MIT License - 可以自由使用、修改和分发

---

**发布日期**: 2026-03-05  
**版本**: v2.2.0  
**开发者**: h1s97x
