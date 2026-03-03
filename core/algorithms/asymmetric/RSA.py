import logging
from PyQt5 import QtCore
# TODO: mm_rsa 模块已被删除，需要重新实现或使用 cryptography 库替代
# from PublicKeyCryptography import mm_rsa

# 临时占位符，防止导入错误
class mm_rsa:
    @staticmethod
    def newkeys(size, shift_select=False):
        raise NotImplementedError("RSA 功能需要重新实现")
    
    @staticmethod
    def encrypt(data, key):
        raise NotImplementedError("RSA 功能需要重新实现")
    
    @staticmethod
    def decrypt(data, key):
        raise NotImplementedError("RSA 功能需要重新实现")


class KeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(tuple)

    def __init__(self, parent):
        super(KeyThread, self).__init__(parent)

    def run(self):
        keys = mm_rsa.newkeys(1024, shift_select=False)
        self.call_back.emit(keys)


class RsaThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_bytes, key, encrypt_selected):
        super(RsaThread, self).__init__(parent)
        self.input_bytes = input_bytes
        self.key = key
        self.encrypt_selected = encrypt_selected

    def encrypt(self):
        try:
            encrypted = mm_rsa.encrypt(self.input_bytes, self.key[0])
            temp = ""
            for item in encrypted:
                temp = temp + '{:02X}'.format(int(item)) + " "
            self.call_back.emit(temp.strip())
        except Exception as e:
            logging.debug(e)
            self.call_back.emit("Encrypt Failed")

    def decrypt(self):
        try:
            logging.info("Decrypt thread is running.")
            decrypted = mm_rsa.decrypt(self.input_bytes, self.key[1])
            temp = ""
            for item in decrypted:
                temp = temp + '{:02X}'.format(int(item)) + " "
            self.call_back.emit(temp.strip())
        except Exception as e:
            logging.debug(e)

    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt()
        elif self.encrypt_selected == 1:
            self.decrypt()

