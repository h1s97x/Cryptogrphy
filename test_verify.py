"""
测试 Verify 协议 Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from ui.widgets.protocols.verify_widget import VerifyWidget


def main():
    app = QApplication(sys.argv)
    
    # 创建 Widget
    widget = VerifyWidget()
    widget.setWindowTitle("Verify 协议测试")
    widget.resize(900, 800)
    widget.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
