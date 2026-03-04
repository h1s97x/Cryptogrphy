# 深色主题显示问题修复

## 问题描述

切换到深色主题后，文字显示为白色，但背景仍然是浅色，导致文字看不清。

## 原因分析

QFluentWidgets 的主题切换机制需要窗口正确响应主题变化事件。某些情况下，主题切换后样式没有立即更新。

## 解决方案

### 方案1: 重启应用（推荐）

最简单的方法是在切换主题后重启应用：

1. 在设置中选择想要的主题
2. 关闭程序
3. 重新运行 `python main_fluent.py`

主题设置会被保存，重启后会使用新主题。

### 方案2: 修改默认主题

如果你更喜欢深色主题，可以修改 `main_fluent.py`：

```python
# 将这行
setTheme(Theme.LIGHT)

# 改为
setTheme(Theme.DARK)
```

### 方案3: 使用自动主题

让程序跟随系统主题：

```python
# 在 main_fluent.py 中
setTheme(Theme.AUTO)
```

这样程序会自动跟随 Windows 系统的主题设置。

### 方案4: 添加主题切换提示（已实施）

修改设置界面，在切换主题时提示用户重启：

```python
def changeTheme(self, theme):
    """切换主题"""
    setTheme(theme)
    
    theme_names = {
        Theme.LIGHT: "浅色",
        Theme.DARK: "深色",
        Theme.AUTO: "跟随系统"
    }
    
    # 提示用户重启
    InfoBar.warning(
        title="主题已切换",
        content=f"已切换到{theme_names.get(theme, '未知')}主题，建议重启应用以完全生效",
        parent=self,
        duration=5000
    )
```

## 技术说明

QFluentWidgets 的主题系统基于 Qt 的样式表（QSS）。当主题切换时：

1. `setTheme()` 更新全局主题配置
2. 所有使用 QFluentWidgets 组件的窗口应该自动更新
3. 但某些情况下，已经创建的窗口可能需要手动刷新

## 临时解决方案

如果不想重启，可以尝试：

1. 切换到其他界面（如首页）
2. 再切换回来
3. 某些组件可能会正确显示

## 最佳实践

### 开发时

在开发阶段，建议：
- 使用 `Theme.AUTO` 跟随系统
- 或者固定使用一个主题进行开发

### 生产环境

在发布版本中：
- 默认使用 `Theme.LIGHT`（浅色主题）
- 或者使用 `Theme.AUTO`（跟随系统）
- 在设置中提供主题切换选项
- 提示用户切换主题后需要重启

## 代码示例

### 修改默认主题为深色

`main_fluent.py`:
```python
def main():
    app = QApplication(sys.argv)
    
    # 设置字体
    font = QFont('Microsoft YaHei UI', 10)
    app.setFont(font)
    
    # 设置主题色
    setThemeColor(QColor(0, 120, 212))
    
    # 使用深色主题
    setTheme(Theme.DARK)  # 改为深色
    
    window = FluentMainWindow()
    window.show()
    
    sys.exit(app.exec_())
```

### 修改默认主题为自动

`main_fluent.py`:
```python
def main():
    app = QApplication(sys.argv)
    
    # 设置字体
    font = QFont('Microsoft YaHei UI', 10)
    app.setFont(font)
    
    # 设置主题色
    setThemeColor(QColor(0, 120, 212))
    
    # 跟随系统主题
    setTheme(Theme.AUTO)  # 自动跟随系统
    
    window = FluentMainWindow()
    window.show()
    
    sys.exit(app.exec_())
```

## 验证主题

### 浅色主题应该显示
- 主背景: 浅灰色 (#F3F3F3)
- 卡片背景: 白色 (#FFFFFF)
- 文字: 深色 (#000000)
- 按钮: 蓝色

### 深色主题应该显示
- 主背景: 深灰色 (#202020)
- 卡片背景: 中灰色 (#2D2D2D)
- 文字: 浅色 (#FFFFFF)
- 按钮: 蓝色

## 常见问题

**Q: 为什么切换主题后显示不正常？**

A: QFluentWidgets 的主题切换需要重新初始化某些组件。建议重启应用。

**Q: 可以在运行时完美切换主题吗？**

A: 理论上可以，但需要更复杂的实现。当前版本建议重启应用。

**Q: 如何保存用户的主题选择？**

A: 可以使用 QSettings 保存用户偏好：

```python
from PyQt5.QtCore import QSettings

# 保存主题
settings = QSettings("YourCompany", "CryptoApp")
settings.setValue("theme", "dark")

# 读取主题
theme = settings.value("theme", "light")
```

## 推荐配置

对于大多数用户，推荐使用：

```python
# main_fluent.py
setTheme(Theme.AUTO)  # 跟随系统
```

这样：
- 白天自动使用浅色主题
- 晚上自动使用深色主题
- 无需手动切换
- 体验最佳

## 总结

当前最简单的解决方案：

1. ✅ 使用 `Theme.AUTO` 跟随系统（推荐）
2. ✅ 或者固定使用 `Theme.LIGHT` 或 `Theme.DARK`
3. ✅ 如果需要切换主题，重启应用

未来可以考虑：
- 实现更完善的主题切换机制
- 添加主题切换动画
- 保存用户主题偏好
