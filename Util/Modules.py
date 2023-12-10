import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QLineEdit, QMainWindow, \
    QAction, QMessageBox, QStackedWidget, QComboBox
from PyQt5.QtGui import QPainter, QPixmap
from PyQt5.QtCore import Qt



class KeyGroup(QWidget):
    def __init__(self, name, key_edit, combo_box, buttons):
        super().__init__()
        self.name = name
        self.key_edit = key_edit
        self.combo_box = combo_box
        self.buttons = buttons
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        for key in self.key_edit:
            label = QLabel(key.label)
            edit = QLineEdit(key.text)
            if not key.enabled:
                edit.setDisabled(True)
            layout.addWidget(label)
            layout.addWidget(edit)
        self.setLayout(layout)
        self.setWindowTitle(self.name)

class Group(QWidget):
    def __init__(self, name, plain_text_edits, buttons):
        super().__init__()
        self.name = name
        self.plain_text_edits = plain_text_edits
        self.buttons = buttons
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        group_label = QLabel(self.name)
        layout.addWidget(group_label)

        for edit in self.plain_text_edits:
            label = QLabel(edit.label)
            text_edit = QTextEdit(edit.text)
            if edit.read_only:
                text_edit.setReadOnly(True)
            layout.addWidget(label)
            layout.addWidget(text_edit)

        for button in self.buttons:
            button_widget = QPushButton(button.name)
            button_widget.clicked.connect(button.clicked_function)
            layout.addWidget(button_widget)

        self.setLayout(layout)

class Key:
    def __init__(self, id, label, default_text, enabled=True, read_only=False):
        self.enabled = enabled
        self.id = id
        self.label = label
        self.text = default_text
        self.read_only = read_only

class PlainTextEdit:
    def __init__(self, id, label, default_text, read_only=False):
        self.id = id
        self.label = label
        self.text = default_text
        self.read_only = read_only


    def get_text(self):
        return self.text

    def set_text(self, text):
        if not self.read_only:
            self.text = text


class Button:
    def __init__(self, id, name, clicked_function):
        self.id = id
        self.name = name
        self.clicked_function = clicked_function

class ComboBox:
    def __init__(self, enabled, id, label, items, changed_function=None):
        self.enabled = enabled
        self.id = id
        self.label = label
        self.items = items
        self.changed_function = changed_function


    def get_id(self):
        return self.id

    def set_id(self, id):
        self.id = id

    def get_label(self):
        return self.label

    def set_label(self, label):
        self.label = label

    def get_items(self):
        return self.items

    def set_items(self, items):
        self.items = items

class Error:
    def __init__(self, value):
        self.value = value
class ErrorType:
    SmartCardConnectError = Error("SmartCardConnectError")
    NotMeetRequirementError = Error("NotMeetRequirementError")
    CharacterError = Error("CharacterError")
    LengthError = Error("LengthError")

class Logging:
    def __init__(self, log_widget):
        self.log_widget = log_widget

    def log(self, message):
        self.log_widget.append_log_message(message)

    def log_error(self, error):
        error_message = str(error)
        self.log_widget.append_error_message(error_message)

class LoggingWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Logging Widget")
        self.setGeometry(300, 300, 500, 400)

        self.log_text_edit = QTextEdit(self)
        self.log_text_edit.setReadOnly(True)  # 设置为只读模式
        self.log_text_edit.setPlaceholderText("Log messages will be displayed here.")

        layout = QVBoxLayout(self)
        layout.addWidget(self.log_text_edit)

    def append_log_message(self, message):
        self.log_text_edit.append(message)
    def append_error_message(self, error_message):
        error_prefix = "<span style='color: red;'>Error: </span>"
        formatted_message = f"{error_prefix}{error_message}"
        self.log_text_edit.append(formatted_message)

class TextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)

    def get_text(self):
        text = self.toPlainText()
        return text

    def set_text(self,str_data):
        return self.setText(str_data)
class CryptographyWidget(QMainWindow):
    def __init__(self):
        super().__init__()
        self.groups_config=[]
        self.logging_widget = LoggingWidget()
        self.logging = Logging(self.logging_widget)
        self.initUI()
        self.current_subwidget = None

    def initUI(self):
        # 延迟导入
        import ClassicCrypto
        import BlockCipher
        import PublicKeyCryptography
        import StreamCipher
        import Hash
        # import CryptographicProtocol
        import MathematicalBasis

        self.setWindowTitle("Menu Bar")
        self.setGeometry(300, 300, 500, 400)

        menubar = self.menuBar()

        classic_cipher_menu = menubar.addMenu("Classic Cipher")

        hill_cipher_action = QAction("Hill Cipher", self)
        hill_cipher_action.triggered.connect(lambda: self.handleCipherAction(ClassicCrypto.HillWidget)) # 修改为通用的处理方法
        classic_cipher_menu.addAction(hill_cipher_action)

        caesar_cipher_action = QAction("Caesar Cipher", self)
        caesar_cipher_action.triggered.connect(lambda: self.handleCipherAction(ClassicCrypto.CaesarWidget)) # 修改为通用的处理方法
        classic_cipher_menu.addAction(caesar_cipher_action)

        vigenere_cipher_action = QAction("Vigenere Cipher", self)
        vigenere_cipher_action.triggered.connect(lambda: self.handleCipherAction(ClassicCrypto.VigenereWidget)) # 修改为通用的处理方法
        classic_cipher_menu.addAction(vigenere_cipher_action)

        playfair_cipher_action = QAction("Playfair Cipher", self)
        playfair_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(ClassicCrypto.PlayfairWidget))  # 修改为通用的处理方法
        classic_cipher_menu.addAction(playfair_cipher_action)

        enigma_cipher_action = QAction("Enigma Cipher", self)
        enigma_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(ClassicCrypto.EnigmaWidget))  # 修改为通用的处理方法
        classic_cipher_menu.addAction(enigma_cipher_action)

        monoalphabetic_cipher_action = QAction("Monoalphabetic Cipher", self)
        monoalphabetic_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(ClassicCrypto.MonoalphabeticWidget))  # 修改为通用的处理方法
        classic_cipher_menu.addAction(monoalphabetic_cipher_action)

        FA_cipher_action = QAction("Frequency Analysis", self)
        FA_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(ClassicCrypto.FAWidget))  # 修改为通用的处理方法
        classic_cipher_menu.addAction(FA_cipher_action)


        block_cipher_menu = menubar.addMenu("Block Cipher")

        DES_cipher_action = QAction("DES", self)
        DES_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(BlockCipher.DESWidget))  # 修改为通用的处理方法
        block_cipher_menu.addAction(DES_cipher_action)

        AES_cipher_action = QAction("AES", self)
        AES_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(BlockCipher.AESWidget))  # 修改为通用的处理方法
        block_cipher_menu.addAction(AES_cipher_action)

        block_cipher_action = QAction("Block Mode", self)
        block_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(BlockCipher.BlockModeWidget))  # 修改为通用的处理方法
        block_cipher_menu.addAction(block_cipher_action)

        SM4_cipher_action = QAction("SM4", self)
        SM4_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(BlockCipher.SM4Widget))  # 修改为通用的处理方法
        block_cipher_menu.addAction(SM4_cipher_action)

        SIMON_cipher_action = QAction("SIMON", self)
        SIMON_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(BlockCipher.SIMONWidget))  # 修改为通用的处理方法
        block_cipher_menu.addAction(SIMON_cipher_action)

        SPECK_cipher_action = QAction("SPECK", self)
        SPECK_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(BlockCipher.SPECKWidget))  # 修改为通用的处理方法
        block_cipher_menu.addAction(SPECK_cipher_action)


        public_key_cipher_menu = menubar.addMenu("Public Key Cipher")

        RSA_cipher_action = QAction("RSA", self)
        RSA_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.RSAWidget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(RSA_cipher_action)

        RSASign_cipher_action = QAction("RSA signature", self)
        RSASign_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.RSASignWidget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(RSASign_cipher_action)

        SM2_cipher_action = QAction("SM2", self)
        SM2_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.SM2Widget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(SM2_cipher_action)

        SM2Sign_cipher_action = QAction("SM2 signature", self)
        SM2Sign_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.SM2Widget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(SM2Sign_cipher_action)

        ElGamal_cipher_action = QAction("ElGamal", self)
        ElGamal_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.ElGamalWidget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(ElGamal_cipher_action)

        ECC_cipher_action = QAction("ECC", self)
        ECC_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.ECCWidget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(ECC_cipher_action)

        ECDSA_cipher_action = QAction("ECDSA", self)
        ECDSA_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(PublicKeyCryptography.ECDSAWidget))  # 修改为通用的处理方法
        public_key_cipher_menu.addAction(ECDSA_cipher_action)


        hash_algorithm_menu = menubar.addMenu("Hash Algorithm")

        SHA1_cipher_action = QAction("SHA-1", self)
        SHA1_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.SHA1Widget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(SHA1_cipher_action)

        SHA3_cipher_action = QAction("SHA-3", self)
        SHA3_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.SHA3Widget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(SHA3_cipher_action)

        SHA256_cipher_action = QAction("SHA-256", self)
        SHA256_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.SHA256Widget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(SHA256_cipher_action)

        MD5_cipher_action = QAction("MD5", self)
        MD5_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.MD5Widget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(MD5_cipher_action)

        HMACMD5_cipher_action = QAction("HMACMD5", self)
        HMACMD5_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.MD5_HMACWidget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(HMACMD5_cipher_action)

        SM3_cipher_action = QAction("SM3", self)
        SM3_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.SM3Widget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(SM3_cipher_action)

        AES_CBC_MAC_cipher_action = QAction("AES-CBC-MAC", self)
        AES_CBC_MAC_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.AES_CBC_MACWidget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(AES_CBC_MAC_cipher_action)

        PS_cipher_action = QAction("Password System", self)
        PS_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.PSWidget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(PS_cipher_action)

        HR_cipher_action = QAction("Hash Reverse", self)
        HR_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(Hash.HashReverseWidget))  # 修改为通用的处理方法
        hash_algorithm_menu.addAction(HR_cipher_action)


        stream_algorithm_menu = menubar.addMenu("Stream Cipher")

        Crypto1_cipher_action = QAction("Crypto-1", self)
        Crypto1_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(StreamCipher.Crypto1Widget))  # 修改为通用的处理方法
        stream_algorithm_menu.addAction(Crypto1_cipher_action)

        RC4_cipher_action = QAction("RC4", self)
        RC4_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(StreamCipher.RC4Widget))  # 修改为通用的处理方法
        stream_algorithm_menu.addAction(RC4_cipher_action)

        SEAL_cipher_action = QAction("SEAL", self)
        SEAL_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(StreamCipher.SEALWidget))  # 修改为通用的处理方法
        stream_algorithm_menu.addAction(SEAL_cipher_action)

        ZUC_cipher_action = QAction("ZUC", self)
        ZUC_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(StreamCipher.ZUCWidget))  # 修改为通用的处理方法
        stream_algorithm_menu.addAction(ZUC_cipher_action)

        math_algorithm_menu = menubar.addMenu("Mathematical Basis")

        CRT_cipher_action = QAction("CRT", self)
        CRT_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(MathematicalBasis.CRTWidget))  # 修改为通用的处理方法
        math_algorithm_menu.addAction(CRT_cipher_action)

        Euler_cipher_action = QAction("Euler", self)
        Euler_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(MathematicalBasis.EulerWidget))  # 修改为通用的处理方法
        math_algorithm_menu.addAction(Euler_cipher_action)

        Euclidean_cipher_action = QAction("Euclidean", self)
        Euclidean_cipher_action.triggered.connect(
            lambda: self.handleCipherAction(MathematicalBasis.EuclideanWidget))  # 修改为通用的处理方法
        math_algorithm_menu.addAction(Euclidean_cipher_action)

        protocol_algorithm_menu = menubar.addMenu("Cryptographic Protocol")

        # DH_cipher_action = QAction("Diffie Hellman", self)
        # DH_cipher_action.triggered.connect(
        #     lambda: self.handleCipherAction(CryptographicProtocol.DHWidget))  # 修改为通用的处理方法
        # protocol_algorithm_menu.addAction(DH_cipher_action)
        #

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.show()
    def logging_error(self, error):
        self.logging.log_error(error)

    def pop_message_box(self, message):
        QMessageBox.critical(self, "Error", message)

    def handleCipherAction(self, widget_class):
        widget = widget_class()  # 创建子窗口实例
        self.setCentralWidget(widget)  # 设置子窗口为中央部件

    def closeEvent(self, event):
        if hasattr(self, 'current_widget') and isinstance(self.current_widget, QWidget):
            self.current_widget.close()
        event.accept()

    def render(self) -> None:
        layout = QVBoxLayout()
        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        for group_config in self.groups_config:
            group_label = QLabel(group_config.name)
            layout.addWidget(group_label)

            if isinstance(group_config, KeyGroup):
                for edit in group_config.key_edit:
                    edit_label = QLabel(edit.label)
                    layout.addWidget(edit_label)

                    edit_text = edit.text
                    edit_widget = TextEdit(edit_text)  # 使用QLineEdit或其他适当的小部件替换此处的QLabel
                    layout.addWidget(edit_widget)

                    self.widgets_dict[edit.id] = edit_widget  # 将小部件与edit对象关联起来

                for combo in group_config.combo_box:
                    combo_label = QLabel(combo.label)
                    layout.addWidget(combo_label)

                    combo_items = combo.items
                    combo_widget = QComboBox()
                    combo_widget.addItems(combo_items)
                    layout.addWidget(combo_widget)

                    self.widgets_dict[combo.id] = combo_widget  # 将小部件与combo对象关联起来
                    combo_widget.currentIndexChanged.connect(combo.changed_function)  # 添加这一行以关联信号和槽函数

            if isinstance(group_config, Group):
                for plain_text_edit in group_config.plain_text_edits:
                    self.widgets_dict[plain_text_edit.id] = plain_text_edit
                    edit_label = QLabel(plain_text_edit.label)
                    layout.addWidget(edit_label)

                    edit_text = plain_text_edit.text
                    edit_widget = TextEdit(edit_text)
                    layout.addWidget(edit_widget)
                    self.widgets_dict[plain_text_edit.id] = edit_widget  # 将QTextEdit小部件与plain_text_edit对象关联起来

            for button in group_config.buttons:
                self.widgets_dict[button.id] = button
                button_widget = QPushButton(button.name)
                button_widget.clicked.connect(button.clicked_function)
                layout.addWidget(button_widget)

        layout.addWidget(self.logging.log_widget)

        self.setGeometry(300, 300, 500, 400)
        self.show()

if __name__ == '__main__':
    app = QApplication([])
    window = CryptographyWidget()
    app.exec_()

