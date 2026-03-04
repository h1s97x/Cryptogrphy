"""
测试数字证书协议Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from ui.widgets.protocols.digital_certificate_widget import DigitalCertificateWidget

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # 创建Widget
    widget = DigitalCertificateWidget()
    widget.setWindowTitle("数字证书测试")
    widget.resize(1000, 800)
    widget.show()
    
    sys.exit(app.exec_())
