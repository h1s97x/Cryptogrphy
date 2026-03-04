# UI使用指南

## 快速开始

### 启动程序

```bash
python main.py
```

### 启动选项

```bash
# 自动主题（默认，跟随系统）
python main.py

# 浅色主题
python main.py --theme light

# 深色主题
python main.py --theme dark
```

## Fluent UI

**特点**:
- ✅ 现代化 Fluent Design 风格
- ✅ 侧边栏导航
- ✅ 卡片式布局
- ✅ 深色/浅色主题支持
- ✅ 流畅的动画效果
- ✅ 更好的用户体验

**启动**: `python main.py`

## 主题说明

### 自动主题 (默认)

跟随 Windows 系统主题自动切换：
- 白天 → 浅色主题
- 晚上 → 深色主题

```bash
python main.py
# 或
python main.py --theme auto
```

### 浅色主题

固定使用浅色主题：

```bash
python main.py --theme light
```

**适合**:
- 白天使用
- 明亮环境
- 长时间阅读

### 深色主题

固定使用深色主题：

```bash
python main.py --theme dark
```

**适合**:
- 夜间使用
- 暗光环境
- 减少眼睛疲劳

## 在程序中切换主题

1. 点击侧边栏底部的"设置"
2. 选择想要的主题
3. 重启程序以完全生效

## 功能特性

### 算法界面
- Hill 密码（完整实现）
  - 密钥配置
  - 加密/解密
  - 文件导入/导出
  - 实时日志
- 其他算法（待迁移）

### 首页
- 算法统计信息
- 快速开始指南
- 统计卡片展示

### 设置
- 主题切换
- 关于信息

## 常见问题

### Q: 如何切换主题？

A: 
1. 在程序中：设置 → 选择主题 → 重启
2. 启动时指定：`python main.py --theme dark`

### Q: 主题切换后显示不正常？

A: 请重启程序，主题需要重新初始化才能完全生效。

### Q: 如何使用旧版经典UI？

A: 切换到 `classic-ui` 分支：
```bash
git checkout classic-ui
python main.py
```

## 开发说明

### 迁移算法到Fluent UI

参考 `ui/fluent/widgets/hill_widget.py` 作为模板：

1. 创建新的widget文件
2. 使用预制的卡片组件
3. 复用原有算法逻辑
4. 在main_window.py中注册

详见：`docs/guides/QFLUENTWIDGETS_QUICK_START.md`

## 相关文档

- `docs/UI_QFLUENTWIDGETS_PROPOSAL.md` - 技术方案
- `docs/guides/QFLUENTWIDGETS_QUICK_START.md` - 快速开始
- `docs/UI_FLUENT_SUMMARY.md` - 实施总结
- `docs/DARK_THEME_FIX.md` - 主题问题说明

## 总结

- ✅ 使用 Fluent UI
- ✅ 使用自动主题跟随系统
- ✅ 需要固定主题时使用启动参数
- ✅ 旧版UI保存在 `classic-ui` 分支

享受现代化的UI体验！🎨
