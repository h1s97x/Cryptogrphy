from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget

from BlockCipher import AES
from Util.Modules import Button, PlainTextEdit, Key, Group, ErrorType, TextEdit
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class AESWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("AES")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                     plain_text_edits=[Key(enabled=True, id="Key", label="Key (Hex)",
                                   default_text="2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C")],
                     buttons=[
                      Button(id="KeyGenerate", name="KeyGenerate", clicked_function=self.generate_key)
                     ]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34"),
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
        self.logging.log("AES algorithm has been imported.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()
            plaintext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text())
            if plaintext_list is None or plaintext_list == 'ERROR_CHARACTER' or plaintext_list == 'ERROR_LENGTH':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            if len(plaintext_list) != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key_list is None or key_list == 'ERROR_CHARACTER' or key_list == 'ERROR_LENGTH':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            if len(key_list) != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # get text from target widget
            # then convert str to int
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, 16))
            self.logging.log("Plaintext:  " + TypeConvert.int_to_str(plaintext, 16))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, 16))
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, 16))
            # initial AES thread
            thread = AES.Thread(self, plaintext, key, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Ciphertext"].set_text)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            # start AES thread
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            ciphertext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text())
            if ciphertext_list is None or ciphertext_list == 'ERROR_CHARACTER' or ciphertext_list == 'ERROR_LENGTH':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            if len(ciphertext_list) != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key_list is None or key_list == 'ERROR_CHARACTER' or key_list == 'ERROR_LENGTH':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            if len(key_list) != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # get text from target widget
            # then convert str to int
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, 16))
            self.logging.log("Ciphertext: " + TypeConvert.int_to_str(ciphertext, 16))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, 16))
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, 16))
            thread = AES.Thread(self, ciphertext, key, 1)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Plaintext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def print_result_to_logging(self, str_data):
        self.logging.log("Result:     " + str(str_data))
        self.logging.log("\n")


    def set_up_key(self, key):
        self.key = key
        private_key = key
        self.logging.log("Generate key completes.")
        self.logging.log("Key: {}".format(TypeConvert.int_to_str(private_key.key, 16)))
        self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(private_key.key, 16))

    # generate key
    def generate_key(self):
        try:
            thread = AES.KeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

if __name__ == '__main__':
    app = QApplication([])
    window = AESWidget()
    app.exec_()