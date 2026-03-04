from PyQt5.QtWidgets import QApplication

from core.algorithms.symmetric.RC4 import Thread as RC4
from ui.main_window import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType
from ui.main_window import CryptographyWidget
from infrastructure.converters.TypeConvert import *


class RC4Widget(CryptographyWidget):
    def __init__(self):
        super().__init__()
        self.menuBar().setHidden(True)
        self.setWindowTitle("RC4")
        
        self.groups_config = [
            KeyGroup(name="Key",
                  key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                        default_text="4B 65 79 ")],
                     combo_box=[],
                     buttons=[]
                     ),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="50 6C 61 69 6E 74 65 78 74 "),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Hex)",
                                                  default_text=""),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]

        self.render()
        self.log_message("RC4 algorithm has been imported.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging widget
            self.log_message("Encrypt on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Plaintext"].get_text(), 'Plaintext'):
                return

            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len == 0:
                self.log_message(ErrorType.LengthError.value + "Key length cannot be 0.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Key length cannot be 0.")
                return
            plaintext_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text()))
            if plaintext_len == 0:
                self.log_message(ErrorType.LengthError.value + "Plaintext length cannot be 0.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plaintext length cannot be 0.")
                return

            # format input
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, plaintext_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            # get text from target widget
            self.log_message("Plaintext : " + TypeConvert.int_to_str(plaintext, plaintext_len))
            self.log_message("Key :       " + TypeConvert.int_to_str(key, key_len))

            # initial Rc4 thread
            thread = RC4.Thread(self, plaintext, plaintext_len, key, key_len, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_ciphertext)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            # start Rc4 thread
            thread.start()

        except Exception as e:
            self.log_message('Error:' + str(e) + '\n')

    def set_print_ciphertext(self, string):
        self.widgets_dict["_Ciphertext"].set_text(string)
        self.log_message("Ciphertext: " + string)
        self.log_message('\n')

    def set_print_plaintext(self, string):
        self.widgets_dict["_Plaintext"].set_text(string)
        self.log_message("Plaintext:  " + string)
        self.log_message('\n')

    # decrypt on computer
    def computer_decrypt(self):
        try:
            # print the login information to main logging widget
            self.log_message("Decrypt on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Ciphertext"].get_text(), 'Ciphertext'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len == 0:
                self.log_message(ErrorType.LengthError.value + "Key length cannot be 0.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Key length cannot be 0.")
                return
            cipher_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text()))
            if cipher_len == 0:
                self.log_message(ErrorType.LengthError.value + "Ciphertext length cannot be 0.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Ciphertext length cannot be 0.")
                return

            # format input
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, cipher_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))

            # get text from target widget
            self.log_message("Ciphertext: " + TypeConvert.int_to_str(ciphertext, cipher_len))
            self.log_message("Key:        " + TypeConvert.int_to_str(key, key_len))
            thread = RC4.Thread(self, ciphertext, cipher_len, key, key_len, 1)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_plaintext)
            thread.start()
        except Exception as e:
            self.log_message(e)
            self.log_message('Error:' + str(e) + '\n')

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def error_check_str_to_hex_list(self, text: str, input_name: str) -> bool:
        if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
            self.log_message(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            self.pop_message_box(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            return False
        elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
            self.log_message(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.\n')
            self.pop_message_box(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.')
            return False
        elif TypeConvert.str_to_hex_list(text) is None:
            return False
        else:
            return True

if __name__ == '__main__':
    app = QApplication([])
    window = RC4Widget()
    app.exec_()
