"""
测试零知识证明 Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from ui.widgets.protocols.zkp_widget import ZKPWidget


def main():
    app = QApplication(sys.argv)
    
    # 创建 Widget
    widget = ZKPWidget()
    widget.setWindowTitle("零知识证明测试")
    widget.resize(900, 900)
    widget.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
