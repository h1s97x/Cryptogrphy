import sys
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *


class MainWindow(QMainWindow):
    count = 0

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.mdi = QMdiArea()
        self.setCentralWidget(self.mdi)
        menubar = self.menuBar()

        classic_cipher_menu = menubar.addMenu("Classic Cipher")
        classic_cipher_menu.addAction("Caesar Cipher")
        classic_cipher_menu.addAction("Vigenere Cipher")

        block_cipher_menu = menubar.addMenu("Block Cipher")
        block_cipher_menu.addAction("AES")
        block_cipher_menu.addAction("DES")

        public_key_cipher_menu = menubar.addMenu("Public Key Cipher")
        public_key_cipher_menu.addAction("RSA")
        public_key_cipher_menu.addAction("ElGamal")

        hash_algorithm_menu = menubar.addMenu("Hash Algorithm")
        hash_algorithm_menu.addAction("MD5")
        hash_algorithm_menu.addAction("SHA-1")
        hash_algorithm_menu.addAction("SHA-256")

        file = menubar.addMenu("File")
        file.addAction("New")
        file.addAction("cascade")
        file.addAction("Tiled")
        file.triggered[QAction].connect(self.windowaction)
        self.setWindowTitle("MDI demo")

    def windowaction(self, q):
        print("triggered")

        if q.text() == "New":
            MainWindow.count = MainWindow.count + 1
            sub = QMdiSubWindow()
            sub.setWidget(QTextEdit())
            sub.setWindowTitle("subwindow" + str(MainWindow.count))
            self.mdi.addSubWindow(sub)
            sub.show()

        if q.text() == "cascade":
            self.mdi.cascadeSubWindows()

        if q.text() == "Tiled":
            self.mdi.tileSubWindows()


def main():
    app = QApplication(sys.argv)
    ex = MainWindow()
    ex.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()