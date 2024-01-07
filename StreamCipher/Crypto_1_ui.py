from PyQt5.QtWidgets import QApplication

from StreamCipher import Crypto_1
from Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert

class Crypto1Widget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Crypto-1")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Key",
                  key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                        default_text="4B 62 45 CB 95 79"),
                            Key(enabled=True, id="Input", label="Input (Hex)",
                                        default_text="82 6B A0 6C")],
                  combo_box=[],
                  buttons=[]
                  ),

            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="74 65 78 74"),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Hex)",
                                                  default_text="EA 1B 80 39"),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]

        self.render()
        self.logging.log("Crypto-1 algorithm has been imported.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Encrypt on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Input"].get_text(), 'Input'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Ciphertext"].get_text(), 'Ciphertext'):
                return

            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len != 6:
                self.logging.log(ErrorType.LengthError.value + "Key length must be 48 bits.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Key length must be 48 bits.")
                return
            input_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Input"].get_text()))
            if input_len != 4:
                self.logging.log(ErrorType.LengthError.value + "Input length must be 32 bits.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Input length must be 32 bits.")
                return
            plaintext_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text()))
            if plaintext_len != 4:
                self.logging.log(ErrorType.LengthError.value + "Plaintext length must be 32 bits.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plaintext length must be 32 bits.")
                return

            # format input
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, plaintext_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            input = TypeConvert.str_to_int(self.widgets_dict["Input"].get_text())
            self.widgets_dict["Input"].set_text(TypeConvert.int_to_str(input, input_len))

            # get text from target widget
            # then convert str to int
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.logging.log("Plaintext:  " + TypeConvert.int_to_str(plaintext, plaintext_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, key_len))
            input = TypeConvert.str_to_int(self.widgets_dict["Input"].get_text())
            self.logging.log("Input:      " + TypeConvert.int_to_str(input, input_len))

            # initial Crypto-1 thread
            thread = Crypto_1.Thread(self, plaintext, plaintext_len, key, key_len, input, input_len, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_ciphertext)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            # 不知道这里的意义，不会改
            # thread.key_stream_result.connect(self.logging)
            # start Crypto-1 thread
            thread.start()

        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_ciphertext(self, string):
        self.widgets_dict["_Ciphertext"].set_text(string)
        self.logging.log("Ciphertext: " + string)
        self.logging.log('\n')

    def set_print_plaintext(self, string):
        self.widgets_dict["_Plaintext"].set_text(string)
        self.logging.log("Plaintext:  " + string)
        self.logging.log('\n')

    # decrypt on computer
    def computer_decrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Decrypt on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Input"].get_text(), 'Input'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Ciphertext"].get_text(), 'Ciphertext'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len != 6:
                self.logging.log(ErrorType.LengthError.value + "Key length must be 48 bits.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Key length must be 48 bits.")
                return
            input_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Input"].get_text()))
            if input_len != 4:
                self.logging.log(ErrorType.LengthError.value + "Input length must be 32 bits.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Input length must be 32 bits.")
                return
            cipher_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text()))
            if cipher_len != 4:
                self.logging.log(ErrorType.LengthError.value + "Ciphertext length must be 32 bits.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Ciphertext length must be 32 bits.")
                return

            # format input
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, cipher_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            input = TypeConvert.str_to_int(self.widgets_dict["Input"].get_text())
            self.widgets_dict["Input"].set_text(TypeConvert.int_to_str(input, input_len))

            # get text from target widget
            # then convert str to int
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.logging.log("Ciphertext: " + TypeConvert.int_to_str(ciphertext, cipher_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, key_len))
            input = TypeConvert.str_to_int(self.widgets_dict["Input"].get_text())
            self.logging.log("Input:      " + TypeConvert.int_to_str(input, input_len))
            thread = Crypto_1.Thread(self, ciphertext, cipher_len, key, key_len, input, input_len, 1)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_plaintext)
            # 不知道这里的意义，不会改
            # thread.key_stream_result.connect(self.logging)
            thread.start()
        except Exception as e:
            self.logging.log(e)
            self.logging.log('Error:' + str(e) + '\n')

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def error_check_str_to_hex_list(self, text: str, input_name: str) -> bool:
        if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
            self.logging.log(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            self.pop_message_box(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            return False
        elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
            self.logging.log(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.\n')
            self.pop_message_box(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.')
            return False
        elif TypeConvert.str_to_hex_list(text) is None:
            return False
        else:
            return True

if __name__ == '__main__':
    app = QApplication([])
    window = Crypto1Widget()
    app.exec_()
