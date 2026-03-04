from PyQt5.QtWidgets import QApplication

from core.algorithms.symmetric.DES import Thread as DES
from ui.main_window import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, ComboBox
from ui.main_window import CryptographyWidget
from infrastructure.converters.TypeConvert import *

class DESWidget(CryptographyWidget):
    def __init__(self):
        super().__init__()
        self.menuBar().setHidden(True)
        self.setWindowTitle("DES")
        
        self.groups_config = [
            KeyGroup(name="Key",
                     key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                   default_text="0F 15 71 C9 47 D9 E8 59")],
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                                         items=["DES", "3-DES"], changed_function=self.combox_changed)],
                     buttons=[]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="02 46 8A CE EC A8 64 20"),
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
        self.log_message("DES algorithm has been imported.\n")

    # when combobox changed
    def combox_changed(self):
        if self.widgets_dict["ComboBox"].currentIndex():
            self.widgets_dict["Key"].set_text("0F 15 71 C9 47 D9 E8 59 0F 15 71 C9 47 D9 E8 59 0F 15 71 C9 47 D9 E8 59")
        else:
            self.widgets_dict["Key"].set_text("0F 15 71 C9 47 D9 E8 59")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.log_message("Encrypt on your computer.")

            if not self.error_check_str_to_hex_list(self.widgets_dict["Plaintext"].get_text(), 'Plaintext'):
                return
            plaintext_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text()))
            if plaintext_len != 8:
                self.log_message(ErrorType.LengthError.value + "Plaintext length must be 8.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plaintext length must be 8.")
                return

            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            encryption_mode = self.widgets_dict["ComboBox"].currentIndex()  # 0-DES, 1-3Des
            if encryption_mode == 0:
                if key_len != 8:
                    self.log_message(ErrorType.LengthError.value + "Key length must be 8.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 8.")
                    return
            else:
                if key_len != 24:
                    self.log_message(ErrorType.LengthError.value + "Key length must be 8. Key length must be 24.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 24.")
                    return
            # format input
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, plaintext_len))
            self.log_message("Plaintext:  " + self.widgets_dict["Plaintext"].get_text())
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            self.log_message("Key:        " + self.widgets_dict["Key"].get_text())

            # initial DES thread
            thread = DES.Thread(self, plaintext, plaintext_len, key, key_len, 0, encryption_mode)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_ciphertext)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            # start html thread
            thread.start()

        except Exception as e:
            self.log_message('Error:' + str(e) + '\n')

    def set_print_ciphertext(self, string):
        self.widgets_dict["_Ciphertext"].set_text(string)
        self.log_message("Ciphertext: " + string)
        self.log_message('\n')

    # decrypt on computer
    def computer_decrypt(self):
        try:
            # print the login information to main logging.log widget
            self.log_message("Decrypt on your computer.")

            if not self.error_check_str_to_hex_list(self.widgets_dict["Ciphertext"].get_text(), 'Ciphertext'):
                return
            cipher_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text()))
            if cipher_len != 8:
                self.log_message(ErrorType.LengthError.value + "Ciphertext length must be 8.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Ciphertext length must be 8.")
                return

            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            encryption_mode = self.widgets_dict["ComboBox"].currentIndex()  # 0-DES, 1-3Des
            if encryption_mode == 0:
                if key_len != 8:
                    self.log_message(ErrorType.LengthError.value + "Key length must be 8.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 8.")
                    return
            else:
                if key_len != 24:
                    self.log_message(ErrorType.LengthError.value + "Key length must be 24.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 24.")
                    return

            # format input
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, cipher_len))
            self.log_message("Ciphertext: " + TypeConvert.int_to_str(ciphertext, cipher_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            self.log_message("Key:        " + TypeConvert.int_to_str(key, key_len))

            thread = DES.Thread(self, ciphertext, cipher_len, key, key_len, 1, encryption_mode)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_plaintext)
            thread.start()
        except Exception as e:
            self.log_message('Error:' + str(e) + '\n')

    def set_print_plaintext(self, string):
        self.widgets_dict["_Plaintext"].set_text(string)
        self.log_message("Plaintext:  " + string)
        self.log_message('\n')

    # clean widget int_data
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget int_data
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
    window = DESWidget()
    app.exec_()