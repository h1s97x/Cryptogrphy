# GitHub Release 发布指南

本文档说明如何将密码学平台发布到 GitHub Releases。

## 准备工作

### 1. 确保代码已提交

```bash
git status  # 检查是否有未提交的更改
git add .
git commit -m "your message"
```

### 2. 更新版本信息

确保以下文件中的版本号正确：
- `RELEASE_NOTES.md`
- `RELEASE_README.md`
- `USER_GUIDE.md`
- `prepare_release.bat`

## 自动发布（推荐）

### 使用准备脚本

双击运行 `prepare_release.bat`，脚本会自动：

1. ✅ 推送代码到 GitHub
2. ✅ 创建版本标签（如 v2.2.0）
3. ✅ 推送标签到 GitHub
4. ✅ 打包应用生成 ZIP

完成后，按照提示访问 GitHub 创建 Release。

## 手动发布

### 步骤 1: 推送代码

```bash
# 推送到 main 分支
git push origin main
```

### 步骤 2: 创建标签

```bash
# 创建带注释的标签
git tag -a v2.2.0 -m "Release v2.2.0 - 完整功能版本"

# 推送标签
git push origin v2.2.0
```

### 步骤 3: 打包应用

```bash
# 运行打包脚本
build.bat

# 或手动打包
pyinstaller build_config.spec --clean
```

### 步骤 4: 创建 GitHub Release

1. **访问 Releases 页面**
   ```
   https://github.com/h1s97x/PyCryptoLab/releases
   ```

2. **点击 "Draft a new release"**

3. **填写 Release 信息**

   - **Choose a tag**: 选择 `v2.2.0`（或点击创建新标签）
   
   - **Release title**: `密码学平台 v2.2.0`
   
   - **Description**: 复制 `RELEASE_NOTES.md` 的内容
   
   - **Attach binaries**: 上传 `dist/密码学平台.zip`

4. **发布选项**

   - ☐ Set as a pre-release（预发布版本）
   - ☑ Set as the latest release（最新版本）

5. **点击 "Publish release"**

## Release 内容模板

### 标题
```
密码学平台 v2.2.0
```

### 描述（Markdown格式）

```markdown
## 🎉 密码学平台 v2.2.0 发布

这是一个重大更新版本，完成了所有密码协议的 Fluent UI 重构。

### ✨ 主要更新

- ✅ 完成 7 个密码协议 Fluent UI 重构
- ✅ 新增数字证书、DH密钥交换等协议
- ✅ 优化项目结构，清理过时代码
- ✅ 提供 Windows 可执行应用

### 📦 下载

**可执行应用**（推荐）:
- 下载 `密码学平台.zip`
- 解压后双击 `密码学平台.exe`
- 无需 Python 环境

**系统要求**:
- Windows 10/11 (64位)
- 约 200MB 磁盘空间

### 📖 文档

- [用户手册](USER_GUIDE.md)
- [完整更新日志](RELEASE_NOTES.md)

### 🐛 已知问题

- 首次启动需要 10-20 秒
- 可能被杀毒软件误报（请添加白名单）

---

**完整更新内容**: 查看 [RELEASE_NOTES.md](RELEASE_NOTES.md)
```

## 上传文件

### 必需文件

- `密码学平台.zip` - 可执行应用（约 80-120 MB）

### 可选文件

- `Source code (zip)` - GitHub 自动生成
- `Source code (tar.gz)` - GitHub 自动生成

## 发布后操作

### 1. 验证 Release

访问 Release 页面，确认：
- ✅ 标签正确
- ✅ 文件可下载
- ✅ 描述完整
- ✅ 标记为最新版本

### 2. 测试下载

- 下载 ZIP 文件
- 解压并运行
- 验证功能正常

### 3. 更新文档

在 README.md 中添加下载链接：

```markdown
## 下载

最新版本: [v2.2.0](https://github.com/h1s97x/PyCryptoLab/releases/latest)
```

### 4. 通知用户

- 在项目主页更新
- 在相关社区发布
- 通知测试用户

## 版本管理

### 版本号规则

使用语义化版本号：`MAJOR.MINOR.PATCH`

- **MAJOR**: 重大更新，不兼容的 API 变更
- **MINOR**: 新功能，向后兼容
- **PATCH**: 问题修复，向后兼容

示例：
- `v2.2.0` - 新增功能（密码协议重构）
- `v2.2.1` - 修复 bug
- `v3.0.0` - 重大架构变更

### 标签命名

- 正式版本: `v2.2.0`
- 预发布版本: `v2.2.0-beta.1`
- 候选版本: `v2.2.0-rc.1`

## 常见问题

### Q1: 标签已存在

```bash
# 删除本地标签
git tag -d v2.2.0

# 删除远程标签
git push origin :refs/tags/v2.2.0

# 重新创建
git tag -a v2.2.0 -m "Release v2.2.0"
git push origin v2.2.0
```

### Q2: 上传文件失败

- 检查文件大小（GitHub 限制 2GB）
- 检查网络连接
- 尝试使用 GitHub CLI

### Q3: Release 需要修改

- 点击 "Edit release"
- 修改内容
- 点击 "Update release"

### Q4: 删除 Release

- 点击 "Delete"
- 确认删除
- 标签仍会保留（需单独删除）

## 使用 GitHub CLI（可选）

### 安装 GitHub CLI

```bash
# Windows (使用 winget)
winget install GitHub.cli

# 或下载安装包
https://cli.github.com/
```

### 登录

```bash
gh auth login
```

### 创建 Release

```bash
# 创建 Release 并上传文件
gh release create v2.2.0 \
  "dist/密码学平台.zip" \
  --title "密码学平台 v2.2.0" \
  --notes-file RELEASE_NOTES.md
```

### 查看 Release

```bash
gh release view v2.2.0
```

### 删除 Release

```bash
gh release delete v2.2.0
```

## 自动化发布（高级）

### GitHub Actions

创建 `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Build application
        run: |
          pip install pyinstaller
          pyinstaller build_config.spec
      
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: dist/密码学平台.zip
          body_path: RELEASE_NOTES.md
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 检查清单

发布前确认：

- [ ] 所有代码已提交
- [ ] 版本号已更新
- [ ] CHANGELOG 已更新
- [ ] 应用已打包测试
- [ ] 文档已更新
- [ ] 标签已创建
- [ ] Release 已发布
- [ ] 下载链接可用
- [ ] 功能测试通过

---

**最后更新**: 2026-03-05  
**适用版本**: v2.2.0
