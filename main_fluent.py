"""
密码学平台 - 统一启动入口

支持三种启动模式：
1. 经典UI: python main.py --ui classic
2. Fluent UI (浅色): python main.py --ui fluent
3. Fluent UI (深色): python main.py --ui fluent --theme dark
4. Fluent UI (自动): python main.py --ui fluent --theme auto (默认)

简化命令：
- python main.py              # Fluent UI (自动主题)
- python main.py --theme dark # Fluent UI (深色主题)
- python main.py --classic    # 经典UI
"""

import sys
import argparse
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont, QColor


def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='密码学平台')
    parser.add_argument('--ui', choices=['classic', 'fluent'], default='fluent',
                        help='UI类型 (默认: fluent)')
    parser.add_argument('--theme', choices=['light', 'dark', 'auto'], default='auto',
                        help='主题模式 (默认: auto)')
    parser.add_argument('--classic', action='store_true',
                        help='使用经典UI (等同于 --ui classic)')
    
    args = parser.parse_args()
    
    # 处理简化参数
    if args.classic:
        args.ui = 'classic'
    
    # 启动对应的UI
    if args.ui == 'classic':
        launch_classic_ui()
    else:
        launch_fluent_ui(args.theme)


def launch_classic_ui():
    """启动经典UI"""
    print("启动经典UI...")
    from ui.main_window import CryptographyWidget
    
    app = QApplication(sys.argv)
    window = CryptographyWidget()
    window.show()
    sys.exit(app.exec_())


def launch_fluent_ui(theme_mode='auto'):
    """启动Fluent UI"""
    print(f"启动Fluent UI (主题: {theme_mode})...")
    
    try:
        from qfluentwidgets import setTheme, Theme, setThemeColor
        from ui.fluent.main_window import FluentMainWindow
    except ImportError:
        print("错误: 未安装 QFluentWidgets")
        print("请运行: pip install PyQt-Fluent-Widgets")
        sys.exit(1)
    
    # 启用高DPI缩放
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    
    app = QApplication(sys.argv)
    
    # 设置应用字体
    font = QFont('Microsoft YaHei UI', 10)
    app.setFont(font)
    
    # 设置主题色
    setThemeColor(QColor(0, 120, 212))
    
    # 设置主题模式
    theme_map = {
        'light': Theme.LIGHT,
        'dark': Theme.DARK,
        'auto': Theme.AUTO
    }
    setTheme(theme_map.get(theme_mode, Theme.AUTO))
    
    # 创建主窗口
    window = FluentMainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
