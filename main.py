"""
密码学平台 - Fluent UI 启动入口

支持主题选项：
- python main.py              # 自动主题（跟随系统）
- python main.py --theme light # 浅色主题
- python main.py --theme dark  # 深色主题
"""

import sys
import argparse
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont, QColor


def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='密码学平台 - Fluent UI')
    parser.add_argument('--theme', choices=['light', 'dark', 'auto'], default='auto',
                        help='主题模式 (默认: auto)')
    
    args = parser.parse_args()
    
    # 启动 Fluent UI
    launch_fluent_ui(args.theme)


def launch_fluent_ui(theme_mode='auto'):
    """启动Fluent UI"""
    print(f"启动密码学平台 (主题: {theme_mode})...")
    
    try:
        from qfluentwidgets import setTheme, Theme, setThemeColor
        from ui.main_window import FluentMainWindow
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
