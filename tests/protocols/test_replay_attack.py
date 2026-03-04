"""
测试重放攻击 Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from qfluentwidgets import setTheme, Theme
from ui.widgets.protocols import ReplayAttackWidget


def main():
    app = QApplication(sys.argv)
    
    # 设置主题
    setTheme(Theme.AUTO)
    
    # 创建窗口
    widget = ReplayAttackWidget()
    widget.setWindowTitle("重放攻击演示")
    widget.resize(900, 800)
    widget.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
