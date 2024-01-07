from PyQt5 import QtCore
from Crypto.PublicKey import ECC
import binascii
from Util import TypeConvert


def str_add_space(out_str: str) -> str:
    """
    Add a space ever 2 char
    """
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str.strip()


class ECCKeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str, str, str, object, object)

    def __init__(self, parent):
        super(ECCKeyThread, self).__init__(parent)

    def run(self):
        k, K, r, key_A, key_B = self.generate_key()
        self.call_back.emit(str_add_space(k.upper()), str_add_space(K.upper()), str_add_space(r.upper()), key_A, key_B)

    @staticmethod
    def generate_key():
        key_a = ECC.generate(curve='P-256')
        key_b = ECC.generate(curve='P-256')
        private_key = key_a.d  # 私钥
        k = hex(private_key).replace('0x', '')
        public_key = key_a.pointQ  # kG
        K = (hex(public_key.x) + hex(public_key.y)).replace('0x', '')
        r = (hex(key_b.d).replace('0x', ''))
        return k, K, r, key_a, key_b


class ECCEncryptThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, plaintext, key_a, key_b):
        super(ECCEncryptThread, self).__init__(parent)
        self.plaintext = plaintext.encode().hex()
        self.key_a = key_a
        self.key_b = key_b

    def run(self):
        ciphertext = self.encrypt()
        self.call_back.emit(str_add_space(ciphertext.upper()))

    def encrypt(self):
        rK = self.key_a.pointQ.__mul__(self.key_b.d)
        rK_value = int((TypeConvert.int_to_str(rK.x, 32) + TypeConvert.int_to_str(rK.y, 32)).replace(' ', ''), 16)
        c1_value = int(self.plaintext, 16) + rK_value
        c1 = TypeConvert.int_to_str(c1_value, 64).replace(' ', '')
        c2 = (TypeConvert.int_to_str(self.key_b.pointQ.x, 32) + TypeConvert.int_to_str(self.key_b.pointQ.y, 32)).replace(' ', '')
        ciphertext = c2 + c1
        return ciphertext


class ECCDecryptThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, ciphertext, key_a, key_b):
        super(ECCDecryptThread, self).__init__(parent)
        self.c2 = ciphertext[0:128]
        self.c1 = ciphertext[128:]
        self.key_a = key_a
        self.key_b = key_b

    def run(self):
        plaintext = self.decrypt()
        self.call_back.emit(plaintext)

    def decrypt(self):
        kc2 = self.key_b.pointQ.__mul__(self.key_a.d)
        plaintext_value = int(self.c1, 16) - int((hex(kc2.x) + hex(kc2.y)).replace('0x', ''), 16)
        plaintext = binascii.unhexlify(hex(plaintext_value).replace('0x', '')).decode()
        return plaintext
