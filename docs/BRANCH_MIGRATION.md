# 分支迁移说明

## 概述

为了保持代码库的整洁，我们将旧的经典UI和新的Fluent UI分离到不同的分支。

## 分支结构

### `main` 分支 - Fluent UI（推荐）

**内容**:
- ✅ 现代化 Fluent Design UI
- ✅ 侧边栏导航
- ✅ 卡片式布局
- ✅ 深色/浅色主题支持
- ✅ 流畅的动画效果

**启动**:
```bash
git checkout main
python main.py
```

**目录结构**:
```
ui/
└── fluent/              # Fluent UI
    ├── main_window.py   # 主窗口
    ├── components/      # 可复用组件
    ├── interfaces/      # 界面页面
    └── widgets/         # 算法界面
```

### `classic-ui` 分支 - 经典UI（备份）

**内容**:
- 传统菜单栏界面
- 完整的37个算法实现
- 所有功能可用

**启动**:
```bash
git checkout classic-ui
python main.py
```

**目录结构**:
```
ui/
├── main_window.py       # 经典UI主窗口
├── widgets/             # 37个算法界面
└── dialogs/             # 对话框
```

### `develop` 分支 - 开发分支

用于日常开发和功能测试。

## 迁移历史

### 2024-XX-XX: 分支分离

1. **创建 `classic-ui` 分支**
   - 保存完整的经典UI代码
   - 包含所有37个算法实现
   - 作为备份和参考

2. **清理 `main` 分支**
   - 删除 `ui/widgets/` (37个旧UI算法界面)
   - 删除 `ui/dialogs/` (旧UI对话框)
   - 删除 `ui/main_window.py` (旧UI主窗口)
   - 删除 `menu.py` (旧UI菜单)
   - 删除 `main_fluent.py` (功能已合并到main.py)
   - 更新 `main.py` 为Fluent UI启动入口
   - 创建新的 `README.md`
   - 更新文档

3. **保留的内容**
   - `core/` - 核心算法实现（两个分支共享）
   - `infrastructure/` - 基础设施（两个分支共享）
   - `CryptographicProtocol/` - 密码协议（两个分支共享）
   - `resources/` - 资源文件（两个分支共享）

## 使用建议

### 对于用户

**推荐使用 `main` 分支的 Fluent UI**:
```bash
git checkout main
python main.py
```

**如果需要使用旧UI或未迁移的算法**:
```bash
git checkout classic-ui
python main.py
```

### 对于开发者

**开发新功能**:
1. 在 `develop` 分支开发
2. 测试通过后合并到 `main`

**迁移算法到Fluent UI**:
1. 参考 `ui/fluent/widgets/hill_widget.py`
2. 从 `classic-ui` 分支查看原实现
3. 在 `main` 分支创建新的Fluent UI实现

**查看旧实现**:
```bash
# 临时切换到 classic-ui 查看
git checkout classic-ui
# 查看完后切回 main
git checkout main
```

## 算法迁移状态

### 已迁移到 Fluent UI
- ✅ Hill 密码

### 待迁移（在 classic-ui 分支可用）
- ⏳ Caesar 密码
- ⏳ Vigenere 密码
- ⏳ Playfair 密码
- ⏳ Enigma 密码
- ⏳ Monoalphabetic 密码
- ⏳ Frequency Analysis
- ⏳ AES
- ⏳ DES
- ⏳ SM4
- ⏳ RC4
- ⏳ SEAL
- ⏳ SIMON
- ⏳ SPECK
- ⏳ ZUC
- ⏳ Crypto_1
- ⏳ Block Mode
- ⏳ RSA
- ⏳ RSA Sign
- ⏳ ECC
- ⏳ ECDSA
- ⏳ ElGamal
- ⏳ SM2
- ⏳ SM2 Sign
- ⏳ MD5
- ⏳ SHA1
- ⏳ SHA256
- ⏳ SHA3
- ⏳ SM3
- ⏳ HMAC-MD5
- ⏳ AES-CBC-MAC
- ⏳ Hash Reverse
- ⏳ CRT
- ⏳ Euclidean
- ⏳ Euler
- ⏳ Password System

## 常见问题

### Q: 为什么要分离分支？

A: 
1. 保持 `main` 分支代码整洁
2. 专注于现代化的 Fluent UI
3. 保留旧UI作为备份和参考
4. 方便用户选择使用哪个版本

### Q: 旧UI还会维护吗？

A: `classic-ui` 分支作为备份保存，不再主动维护。新功能只在 `main` 分支的 Fluent UI 中开发。

### Q: 如何在两个分支之间切换？

A:
```bash
# 切换到 Fluent UI
git checkout main

# 切换到经典UI
git checkout classic-ui

# 查看当前分支
git branch
```

### Q: 核心算法代码在哪里？

A: 核心算法在 `core/algorithms/` 目录，两个分支共享相同的算法实现，只是UI不同。

### Q: 如何贡献代码？

A: 
1. Fork 项目
2. 在 `develop` 分支开发
3. 提交 Pull Request 到 `develop` 分支
4. 审核通过后会合并到 `main`

## 总结

- ✅ `main` 分支 - 现代化 Fluent UI（推荐）
- ✅ `classic-ui` 分支 - 经典UI（备份）
- ✅ `develop` 分支 - 开发分支
- ✅ 核心算法代码在两个分支共享
- ✅ 新功能只在 `main` 分支开发

选择适合你的分支，享受密码学学习之旅！🚀
