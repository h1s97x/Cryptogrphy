import logging
from PyQt5 import QtCore
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class KeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(tuple)

    def __init__(self, parent):
        super(KeyThread, self).__init__(parent)

    def run(self):
        """生成RSA密钥对"""
        try:
            # 使用pycryptodome生成1024位RSA密钥对
            key = CryptoRSA.generate(1024)
            public_key = key.publickey()
            
            # 返回(公钥, 私钥)元组
            keys = (public_key, key)
            self.call_back.emit(keys)
        except Exception as e:
            logging.error(f"密钥生成失败: {e}")
            self.call_back.emit((None, None))


class RsaThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_bytes, key, encrypt_selected):
        super(RsaThread, self).__init__(parent)
        self.input_bytes = input_bytes
        self.key = key
        self.encrypt_selected = encrypt_selected

    def encrypt(self):
        """RSA加密"""
        try:
            # key[0]是公钥
            public_key = self.key[0]
            cipher = PKCS1_OAEP.new(public_key)
            
            # 将输入转换为bytes
            if isinstance(self.input_bytes, str):
                data = self.input_bytes.encode('utf-8')
            else:
                data = self.input_bytes
            
            # RSA加密有长度限制，需要分块
            max_length = 86  # 1024位密钥的最大明文长度（字节）
            encrypted_blocks = []
            
            for i in range(0, len(data), max_length):
                block = data[i:i+max_length]
                encrypted_block = cipher.encrypt(block)
                encrypted_blocks.append(encrypted_block)
            
            # 将所有加密块转换为十六进制字符串
            result = ""
            for block in encrypted_blocks:
                for byte in block:
                    result += '{:02X} '.format(byte)
            
            self.call_back.emit(result.strip())
        except Exception as e:
            logging.error(f"加密失败: {e}")
            self.call_back.emit("Encrypt Failed")

    def decrypt(self):
        """RSA解密"""
        try:
            logging.info("Decrypt thread is running.")
            # key[1]是私钥
            private_key = self.key[1]
            cipher = PKCS1_OAEP.new(private_key)
            
            # 将十六进制字符串转换回bytes
            if isinstance(self.input_bytes, str):
                hex_str = self.input_bytes.replace(' ', '')
                data = bytes.fromhex(hex_str)
            else:
                data = self.input_bytes
            
            # RSA解密需要分块（每块128字节，对应1024位密钥）
            block_size = 128
            decrypted_blocks = []
            
            for i in range(0, len(data), block_size):
                block = data[i:i+block_size]
                decrypted_block = cipher.decrypt(block)
                decrypted_blocks.append(decrypted_block)
            
            # 合并所有解密块
            decrypted_data = b''.join(decrypted_blocks)
            
            # 转换为十六进制字符串
            result = ""
            for byte in decrypted_data:
                result += '{:02X} '.format(byte)
            
            self.call_back.emit(result.strip())
        except Exception as e:
            logging.error(f"解密失败: {e}")
            self.call_back.emit("Decrypt Failed")

    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt()
        elif self.encrypt_selected == 1:
            self.decrypt()

