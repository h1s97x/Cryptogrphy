from PyQt5.QtWidgets import QApplication

from BlockCipher.SM4 import SM4
from Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert


class SM4Widget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("SM4")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Key",
                     key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                   default_text="01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10")],
                     combo_box=[],
                     buttons=[]
                     ),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Hex)", default_text=""),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]

        self.render()
        self.logging.log("SM4 algorithm has been imported.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # get text from target widget and print the login information to main logging.log widget and
            self.logging.log("Encrypt on computer.")
            key = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key is None:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            len1 = len(key)
            if not len1 == 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            plaintext = TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text())
            if plaintext is None:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + "You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            len1 = len(plaintext)
            if not len1 == 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            # format input
            self.widgets_dict["Plaintext"].set_text(TypeConvert.hex_list_to_str(plaintext))
            self.logging.log("Plaintext:  " + TypeConvert.hex_list_to_str(plaintext))
            self.widgets_dict["Key"].set_text(TypeConvert.hex_list_to_str(key))
            self.logging.log("Key:        " + TypeConvert.hex_list_to_str(key))
            # initial SM4 thread
            thread = SM4.Thread(self, plaintext, key, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Ciphertext"].set_text)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            # start SM4 thread
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # decrypt on computer
    def computer_decrypt(self):
        try:
            # get text from target widget and print the login information to main logging.log widget and
            self.logging.log("Decrypt on computer.")
            key = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key is None:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            len1 = len(key)
            if not len1 == 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            ciphertext = TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text())
            if ciphertext is None:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + "You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            len1 = len(ciphertext)
            if not len1 == 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            # format input
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.hex_list_to_str(ciphertext))
            self.logging.log("Ciphertext: " + TypeConvert.hex_list_to_str(ciphertext))
            self.widgets_dict["Key"].set_text(TypeConvert.hex_list_to_str(key))
            self.logging.log("Key:        " + TypeConvert.hex_list_to_str(key))
            # initial SM4 thread
            thread = SM4.Thread(self, ciphertext, key, 1)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Plaintext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            # start SM4 thread
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

if __name__ == '__main__':
    app = QApplication([])
    window = SM4Widget()
    app.exec_()
