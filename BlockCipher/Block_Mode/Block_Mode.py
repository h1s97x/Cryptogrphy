import logging
from PyQt5 import QtCore
from Util import TypeConvert
from BlockCipher.AES import AES


def int_to_matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[int(i / 4)].append(byte)
    return matrix


def matrix_to_int(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text


class Thread(AES.Thread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, key, mode_selected, encrypt_selected, block):
        super(Thread, self).__init__(parent, input_text, key, encrypt_selected)
        self.mode_selected = mode_selected
        self.block = block
        self.round_keys = None
        self.change_key(TypeConvert.str_to_int(key))

    # encrypt script
    def encrypt_run(self):
        logging.info("thread running")
        # ECB加密模式
        if self.mode_selected == 0:
            self.print_intermediate_value("ECB Encryption begins")
            self.print_intermediate_value("Plaintext:\n" + self.input_text)
            self.print_intermediate_value("Key:\n" + self.key)
            result = ""
            for i in range(self.block // 16):
                temp_plaintext = self.input_text[48 * i: 48 * i + 47]
                temp_input_text = TypeConvert.str_to_int(temp_plaintext)
                temp_result = self.encrypt(temp_input_text)
                result = result + TypeConvert.int_to_str(temp_result, 16) + " "
                self.print_intermediate_value("Block " + str(i + 1) + ":" + "\n" + TypeConvert.int_to_str(temp_result, 16))
            self.print_intermediate_value("ECB Encrypted:\n" + result.strip())
            self.print_intermediate_value("ECB Encryption completed\n")
        # CBC加密模式
        else:
            self.print_intermediate_value("CBC Encryption begins")
            self.print_intermediate_value("Plaintext:\n" + self.input_text)
            self.print_intermediate_value("Key:\n" + self.key)
            result = ""
            iv = "12233445566778899aabbccddeef1223"  # 定义IV的值，IV为产生第一个密文分组用到的初始向量
            for i in range(self.block // 16):
                temp_plaintext = self.input_text[48 * i: 48 * i + 47]
                if i == 0:
                    temp_input_text = TypeConvert.str_to_int(temp_plaintext) ^ TypeConvert.str_to_int(iv)
                else:
                    temp_input_text = TypeConvert.str_to_int(temp_plaintext) ^ TypeConvert.str_to_int(result[48 * (i - 1): 48 * (i - 1) + 47])
                temp_result = self.encrypt(temp_input_text)
                result = result + TypeConvert.int_to_str(temp_result, 16) + " "
                self.print_intermediate_value("Block " + str(i + 1) + ":" + "\n" + TypeConvert.int_to_str(temp_result, 16))
            self.print_intermediate_value("CBC Encrypted:\n" + result.strip())
            self.print_intermediate_value("CBC Encryption completed\n")
        self.print_final_result(result.strip())

    # decrypt script
    def decrypt_run(self):
        logging.info("thread running")
        # ECB解密模式
        if self.mode_selected == 0:
            self.print_intermediate_value("ECB Decryption begins")
            self.print_intermediate_value("Ciphertext:\n" + self.input_text)
            self.print_intermediate_value("Key:\n" + self.key)
            result = ""
            for i in range(self.block // 16):
                temp_ciphertext = self.input_text[48 * i: 48 * i + 47]
                temp_input_text = TypeConvert.str_to_int(temp_ciphertext)
                temp_result = self.decrypt(temp_input_text)
                result = result + TypeConvert.int_to_str(temp_result, 16) + " "
                self.print_intermediate_value("Block " + str(i + 1) + ":" + "\n" + TypeConvert.int_to_str(temp_result, 16))
            self.print_intermediate_value("ECB Decrypted:\n" + result.strip())
            self.print_intermediate_value(" ECB Decryption completed\n")
        # CBC解密模式
        else:
            self.print_intermediate_value("CBC Decryption begins")
            self.print_intermediate_value("Ciphertext:\n" + self.input_text)
            self.print_intermediate_value("Key:\n" + self.key)
            result = ""
            iv = "12233445566778899aabbccddeef1223"  # 定义IV的值，IV为产生第一个密文分组用到的初始向量
            for i in range(self.block // 16):
                temp_ciphertext = self.input_text[48 * i: 48 * i + 47]
                temp_input_text = TypeConvert.str_to_int(temp_ciphertext)
                temp_result = self.decrypt(temp_input_text)
                if i == 0:
                    temp_result = temp_result ^ TypeConvert.str_to_int(iv)
                else:
                    temp_result = temp_result ^ TypeConvert.str_to_int(self.input_text[48 * (i - 1): 48 * (i - 1) + 47])
                result = result + TypeConvert.int_to_str(temp_result, 16) + " "
                self.print_intermediate_value("Block " + str(i + 1) + ":" + "\n" + TypeConvert.int_to_str(temp_result, 16))
            self.print_intermediate_value("CBC Decrypted:\n" + result.strip())
            self.print_intermediate_value("CBC Decryption completed\n")
        self.print_final_result(result.strip())

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        else:
            self.decrypt_run()

    def encrypt(self, plaintext):
        temp_text = int_to_matrix(plaintext)
        self.__add_round_key(temp_text, self.round_keys[:4])
        for i in range(1, 10):
            self.__round_encrypt(temp_text, self.round_keys[4 * i: 4 * (i + 1)])
        self.__sub_bytes(temp_text)
        self.__shift_rows(temp_text)
        self.__add_round_key(temp_text, self.round_keys[40:])
        return matrix_to_int(temp_text)

    def decrypt(self, ciphertext):
        temp_text = int_to_matrix(ciphertext)
        self.__add_round_key(temp_text, self.round_keys[40:])
        self.__inv_shift_rows(temp_text)
        self.__inv_sub_bytes(temp_text)
        for i in range(9, 0, -1):
            self.__round_decrypt(temp_text, self.round_keys[4 * i: 4 * (i + 1)])
        self.__add_round_key(temp_text, self.round_keys[:4])
        return matrix_to_int(temp_text)
