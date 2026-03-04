from PyQt5.QtWidgets import QApplication

from core.algorithms.symmetric.SEAL import Thread as SEAL
from ui.main_window import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType
from ui.main_window import CryptographyWidget
from infrastructure.converters.TypeConvert import *

class SEALWidget(CryptographyWidget):
    def __init__(self):
        super().__init__()
        self.menuBar().setHidden(True)
        self.setWindowTitle("SEAL")
        self.PlainLen = int(128 / 8)
        self.KeyLen = int(160 / 8)
        
        self.groups_config = [
            KeyGroup(name="Key",
                  key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                        default_text="30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39")],
                  combo_box=[],
                  buttons=[]
                     ),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35"),
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
        self.log_message("SEAL algorithm has been imported.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging widget
            self.log_message("Encrypt on your computer.")
            self.encrypt_clean()

            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.log_message("\n")
                return
            temp = len(key_list)
            if temp != self.KeyLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box." + str(temp))
                self.log_message("\n")
                return
            plaintext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text())
            if plaintext_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Plaintext\" input box.")
                self.log_message("\n")
                return
            temp = len(plaintext_list)
            if temp != self.PlainLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Plaintext\" input box.")
                self.log_message("\n")
                return
            # get text from target widget
            # then convert str to int
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, self.PlainLen))
            self.log_message("Plaintext:  " + TypeConvert.int_to_str(plaintext, self.PlainLen))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, self.KeyLen))
            self.log_message("Key:        " + TypeConvert.int_to_str(key, self.KeyLen))
            # initial AES thread
            thread = SEAL.Thread(self, plaintext, key, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Ciphertext"].set_text)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            # start AES thread
            thread.start()
        except Exception as e:
            self.logging_error(e)

    def print_result_to_logging(self, str_data):
        self.log_message("Result:     " + str(str_data))
        self.log_message("\n")

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.log_message("Decrypt on your computer.")
            self.decrypt_clean()
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.log_message("\n")
                return
            temp = len(key_list)
            if temp != self.KeyLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                self.log_message("\n")
                return
            ciphertext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text())
            if ciphertext_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Ciphertext\" input box.")
                self.log_message("\n")
                return
            temp = len(ciphertext_list)
            if temp != self.PlainLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Ciphertext\" input box.")
                self.log_message("\n")
                return
            # get text from target widget
            # then convert str to int
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, self.PlainLen))
            self.log_message("Ciphertext: " + TypeConvert.int_to_str(ciphertext, self.PlainLen))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, self.KeyLen))
            self.log_message("Key:        " + TypeConvert.int_to_str(key, self.KeyLen))
            thread = SEAL.Thread(self, ciphertext, key, 1)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Plaintext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            thread.start()
        except Exception as e:
            self.logging_error(e)

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = SEALWidget()
    app.exec_()
