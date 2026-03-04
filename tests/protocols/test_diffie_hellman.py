"""
测试 Diffie-Hellman Widget
"""

import sys
from PyQt5.QtWidgets import QApplication
from ui.widgets.protocols.diffie_hellman_widget import DiffieHellmanWidget


def main():
    app = QApplication(sys.argv)
    
    # 创建 Widget
    widget = DiffieHellmanWidget()
    widget.setWindowTitle("Diffie-Hellman 密钥交换测试")
    widget.resize(900, 1000)
    widget.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
