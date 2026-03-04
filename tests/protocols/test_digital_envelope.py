"""
测试数字信封 Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from ui.widgets.protocols.digital_envelope_widget import DigitalEnvelopeWidget


def main():
    app = QApplication(sys.argv)
    
    # 创建 Widget
    widget = DigitalEnvelopeWidget()
    widget.setWindowTitle("数字信封测试")
    widget.resize(900, 1000)
    widget.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
