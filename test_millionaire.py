"""
测试百万富翁问题 Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from ui.widgets.protocols.millionaire_widget import MillionaireWidget


def main():
    app = QApplication(sys.argv)
    
    # 创建 Widget
    widget = MillionaireWidget()
    widget.setWindowTitle("百万富翁问题测试")
    widget.resize(900, 900)
    widget.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
