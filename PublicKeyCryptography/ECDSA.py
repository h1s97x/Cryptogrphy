from PyQt5 import QtCore
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


def str_add_space(out_str: str) -> str:
    """
    Add a space ever 2 char
    """
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str.strip()


class ECDSAKeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str, str, object)

    def __init__(self, parent):
        super(ECDSAKeyThread, self).__init__(parent)

    def run(self):
        pri_key, pub_key, key = self.generate_key()
        self.call_back.emit(str_add_space(pri_key.upper()), str_add_space(pub_key.upper()), key)

    @staticmethod
    def generate_key():
        key = ECC.generate(curve='NIST P-256')  # keya.pointQ:K,keya.d:k

        pri_k = hex(key.d).replace("0x", "")
        pub_k = (hex(key.pointQ.x) + hex(key.pointQ.y)).replace("0x", "")
        return pri_k, pub_k, key


class ECDSASignatureThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, message, key):
        super(ECDSASignatureThread, self).__init__(parent)
        self.message = message
        self.key = key

    def run(self):
        result = self.signature()
        self.call_back.emit(str_add_space(result.upper()))

    def signature(self):
        signer = DSS.new(self.key, 'fips-186-3')  # 包含私钥
        hash_value = SHA256.new(self.message)
        sign_value = signer.sign(hash_value)
        result = sign_value.hex()
        return result


class VerifySignatureThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, message, sign_value, key):
        super(VerifySignatureThread, self).__init__(parent)
        self.message = message
        self.sign_value = sign_value
        self.key = key

    def run(self):
        result = self.verify()
        self.call_back.emit(result)

    def verify(self):
        hasher = SHA256.new(self.message)
        verify_value = DSS.new(self.key.public_key(), 'fips-186-3')
        try:
            verify_value.verify(hasher, self.sign_value)
            return "Verify Success."
        except ValueError:
            return "Verify False."
