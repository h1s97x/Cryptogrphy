import logging
from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, input_text_len, key, key_len, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key_source = key
        self.input_text_len = input_text_len
        self.key_len = key_len
        self.encrypt_selected = encrypt_selected

    # encrypt script
    def encrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Encryption begins")
        self.print_intermediate_value("Plaintext:\n" + TypeConvert.int_to_str(self.input_text, self.input_text_len))
        self.print_intermediate_value("Key:\n" + TypeConvert.int_to_str(self.key_source, self.input_text_len))
        result = self.encrypt()
        self.print_intermediate_value("Encrypted:\n" + TypeConvert.int_to_str(result, self.input_text_len))
        self.print_intermediate_value("Encryption completed\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, self.input_text_len))

    # decrypt script
    def decrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Decryption begins")
        self.print_intermediate_value("Ciphertext:\n" + TypeConvert.int_to_str(self.input_text, self.input_text_len))
        self.print_intermediate_value("Key:\n" + TypeConvert.int_to_str(self.key_source, self.input_text_len))
        result = self.decrypt()
        self.print_intermediate_value("Decrypted:\n" + TypeConvert.int_to_str(result, self.input_text_len))
        self.print_intermediate_value("Decryption completed\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, self.input_text_len))

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

    def encrypt(self):
        plaint_byte = TypeConvert.int_to_hex_list(self.input_text, self.input_text_len)
        key_byte = TypeConvert.int_to_hex_list(self.key_source, self.key_len)
        result = self.encrypt_logic(plaint_byte, key_byte)
        return TypeConvert.hex_list_to_int(result)

    def decrypt(self):
        cipher_byte = TypeConvert.int_to_hex_list(self.input_text, self.input_text_len)
        key_byte = TypeConvert.int_to_hex_list(self.key_source, self.key_len)
        result = self.encrypt_logic(cipher_byte, key_byte)
        return TypeConvert.hex_list_to_int(result)

    # Key Scheduling Algorithm
    @staticmethod
    def KSA(key):
        key_length = len(key)
        # create the array "S"
        S = list(range(256))  # [0,1,2, ... , 255]
        T = list(range(256))  # [0,1,2, ... , 255]
        j = 0
        for i in range(256):
            T[i] = key[i % key_length]
            j = (j + S[i] + T[i]) % 256
            S[i], S[j] = S[j], S[i]  # swap values
        return S, T

    # Psudo Random Generation Algorithm
    @staticmethod
    def PRGA(S):
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]  # swap values
            K = S[(S[i] + S[j]) % 256]
            yield K

    # Takes the encryption key to get the key_stream using PRGA
    # return object is a generator
    def get_key_stream(self, key):
        S, T = self.KSA(key)
        self.print_intermediate_value("S:\n" + TypeConvert.hex_list_to_str(S))
        self.print_intermediate_value("T:\n" + TypeConvert.hex_list_to_str(T))
        return self.PRGA(S)

    def encrypt_logic(self, text, key):
        key_stream = self.get_key_stream(key)
        res = []
        keys = []

        for i in range(len(text)):
            keys.append(next(key_stream))
            val = text[i] ^ keys[i]
            # val = ("%02X" % (plaintext[i] ^ keys[i]))  # XOR and taking hex
            res.append(val)
        self.print_intermediate_value("k:\n" + TypeConvert.hex_list_to_str(keys))
        return res
