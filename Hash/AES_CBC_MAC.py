import logging
from PyQt5 import QtCore
import BlockCipher.Block_Mode as AES_CBC
from Util import TypeConvert


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, message, message_len, key):
        super(Thread, self).__init__(parent)
        self.message = message
        self.message_len = message_len
        self.key = key

    # hash script
    def hash_run(self):
        logging.info("thread running")
        self.print_intermediate_value("AES-CBC-MAC begins")
        self.print_intermediate_value("Message:\n" + TypeConvert.int_to_str(self.message, self.message_len))
        self.print_intermediate_value("Key:\n" + self.key)
        message = TypeConvert.int_to_str(self.message, self.message_len)
        result = ""
        for i in range(0, self.message_len // 16):
            temp_message = message[48 * i: 48 * i + 47]
            if i == 0:
                temp_input_text = TypeConvert.str_to_int(temp_message)
            else:
                temp_input_text = TypeConvert.str_to_int(temp_message) ^ result
            result = self.aes_encrypt(temp_input_text)
            self.print_intermediate_value("Block " + str(i + 1) + ":" + "\n" + TypeConvert.int_to_str(result, 16))
        self.print_final_result(TypeConvert.int_to_str(result, 16))
        self.print_intermediate_value("Hash:\n" + TypeConvert.int_to_str(result, 16))
        self.print_intermediate_value("Hash completed\n\n")

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.hash_run()

    def aes_encrypt(self, plaintext):
        aes = AES_CBC.Thread(self, plaintext, self.key, 1, 0, self.message_len)
        return aes.encrypt(plaintext)
