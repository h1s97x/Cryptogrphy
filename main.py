# Main entry point for the cryptography platform
import sys
from PyQt5.QtWidgets import QApplication
from ui.main_window import CryptographyWidget


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CryptographyWidget()
    window.show()
    sys.exit(app.exec_())
