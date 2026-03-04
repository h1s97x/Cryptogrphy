# 基于 QFluentWidgets 的UI改进方案

## 为什么选择 QFluentWidgets

### 优势
- ✅ 开箱即用的 Fluent Design 风格
- ✅ 丰富的现代化组件库
- ✅ 内置深色/浅色主题
- ✅ 流畅的动画效果
- ✅ 完善的文档和示例
- ✅ 活跃的社区支持
- ✅ 与 PyQt5/PySide6 完美兼容

### 核心组件
- NavigationInterface: 侧边栏导航
- CardWidget: 卡片容器
- PushButton, PrimaryPushButton: 现代化按钮
- LineEdit, TextEdit: 美化的输入框
- MessageBox, InfoBar: 消息提示
- Theme: 主题管理

## 安装

```bash
pip install PyQt-Fluent-Widgets
```

或者添加到 requirements.txt：
```
PyQt-Fluent-Widgets>=1.5.0
```

## 项目结构

```
ui/
├── fluent/
│   ├── __init__.py
│   ├── main_window.py          # 主窗口（带导航）
│   ├── algorithm_interface.py  # 算法界面基类
│   ├── components/
│   │   ├── __init__.py
│   │   ├── key_card.py         # 密钥配置卡片
│   │   ├── encrypt_card.py     # 加密卡片
│   │   ├── decrypt_card.py     # 解密卡片
│   │   └── log_card.py         # 日志卡片
│   └── widgets/
│       ├── __init__.py
│       ├── hill_widget.py      # Hill算法界面
│       ├── caesar_widget.py    # Caesar算法界面
│       └── ...
```

## 设计规范

### 布局结构

```
┌─────────────────────────────────────────────────┐
│  标题栏 (FluentTitleBar)                         │
├──────────┬──────────────────────────────────────┤
│          │                                      │
│  导航栏  │         主内容区                      │
│  (Nav)   │      (ScrollArea)                    │
│          │                                      │
│  🏠 首页 │  ┌────────────────────────────┐     │
│  🔤 经典 │  │  算法标题 + 描述            │     │
│  🔐 分组 │  ├────────────────────────────┤     │
│  🔑 公钥 │  │  📋 密钥配置 (CardWidget)  │     │
│  #️⃣ 哈希 │  ├────────────────────────────┤     │
│  🌊 流密 │  │  🔒 加密 (CardWidget)      │     │
│  🔢 数学 │  ├────────────────────────────┤     │
│  🤝 协议 │  │  🔓 解密 (CardWidget)      │     │
│  ⚙️ 设置 │  └────────────────────────────┘     │
│          │                                      │
└──────────┴──────────────────────────────────────┘
```

### 组件映射

| 原组件 | QFluentWidgets组件 | 说明 |
|--------|-------------------|------|
| QMainWindow | FluentWindow | 主窗口 |
| QWidget | CardWidget | 卡片容器 |
| QPushButton | PrimaryPushButton | 主要按钮 |
| QPushButton | PushButton | 次要按钮 |
| QLineEdit | LineEdit | 单行输入 |
| QTextEdit | TextEdit | 多行输入 |
| QLabel | BodyLabel, CaptionLabel | 文本标签 |
| QComboBox | ComboBox | 下拉框 |
| QMessageBox | MessageBox | 消息框 |
| - | InfoBar | Toast提示 |
| QMenuBar | NavigationInterface | 导航栏 |

## 主题配置

```python
from qfluentwidgets import Theme, setTheme, setThemeColor
from PyQt5.QtGui import QColor

# 设置主题
setTheme(Theme.LIGHT)  # 或 Theme.DARK / Theme.AUTO

# 自定义主题色
setThemeColor(QColor(37, 99, 235))  # 蓝色
```

## 导航结构

```python
NAVIGATION_ITEMS = [
    {
        'routeKey': 'home',
        'text': '首页',
        'icon': FluentIcon.HOME,
        'widget': HomeInterface
    },
    {
        'routeKey': 'classical',
        'text': '经典密码',
        'icon': FluentIcon.FONT,
        'children': [
            {'routeKey': 'hill', 'text': 'Hill', 'widget': HillWidget},
            {'routeKey': 'caesar', 'text': 'Caesar', 'widget': CaesarWidget},
            {'routeKey': 'vigenere', 'text': 'Vigenere', 'widget': VigenereWidget},
            {'routeKey': 'playfair', 'text': 'Playfair', 'widget': PlayfairWidget},
            {'routeKey': 'enigma', 'text': 'Enigma', 'widget': EnigmaWidget},
        ]
    },
    {
        'routeKey': 'block',
        'text': '分组密码',
        'icon': FluentIcon.LOCK,
        'children': [
            {'routeKey': 'des', 'text': 'DES', 'widget': DESWidget},
            {'routeKey': 'aes', 'text': 'AES', 'widget': AESWidget},
            {'routeKey': 'sm4', 'text': 'SM4', 'widget': SM4Widget},
        ]
    },
    # ... 更多分类
]
```

## 迁移策略

### 阶段1: 环境准备
1. 安装 QFluentWidgets
2. 创建新的 ui/fluent 目录
3. 保留原有 ui 代码作为备份

### 阶段2: 创建基础框架
1. 实现 FluentWindow 主窗口
2. 配置导航栏
3. 创建算法界面基类

### 阶段3: 迁移算法界面
1. 选择1-2个简单算法作为试点
2. 使用 QFluentWidgets 组件重写
3. 测试功能完整性
4. 逐步迁移其他算法

### 阶段4: 功能增强
1. 添加首页仪表板
2. 实现设置页面
3. 优化交互体验

## 兼容性考虑

### 保持核心逻辑不变
- 算法实现代码无需修改
- 只改变UI层
- 保持原有的接口和方法

### 渐进式迁移
- 新旧UI可以共存
- 通过命令行参数选择UI版本
- 逐步完成迁移

```python
# main.py
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--ui', choices=['classic', 'fluent'], default='fluent')
args = parser.parse_args()

if args.ui == 'fluent':
    from ui.fluent.main_window import FluentMainWindow as MainWindow
else:
    from ui.main_window import CryptographyWidget as MainWindow
```

## 预期效果

### 视觉改进
- 现代化的 Fluent Design 风格
- 流畅的动画和过渡效果
- 统一的设计语言
- 更好的视觉层次

### 交互改进
- 直观的侧边栏导航
- 响应式的组件反馈
- 优雅的消息提示
- 更好的键盘支持

### 功能增强
- 主题自动切换
- 搜索功能
- 收藏功能
- 历史记录

## 参考资源

- [QFluentWidgets 官方文档](https://qfluentwidgets.com/)
- [GitHub 仓库](https://github.com/zhiyiYo/PyQt-Fluent-Widgets)
- [示例程序](https://github.com/zhiyiYo/PyQt-Fluent-Widgets/tree/master/examples)
- [组件库](https://qfluentwidgets.com/zh/components)
