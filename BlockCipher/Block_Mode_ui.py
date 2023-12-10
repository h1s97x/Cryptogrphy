import logging
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from BlockCipher import Block_Mode
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class BlockModeWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Block Mode")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Key",
                     key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                   default_text="2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C ")],
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Model Select",
                                         items=["ECB", "CBC"], changed_function=self.combox_changed)],
                     buttons=[]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34"),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt(PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Hex)",
                                                  default_text=""),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt(PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]
        self.render()
        self.logging.log("Block mode has been imported.\n")

    def func_encrypt(self, str_data):
        self.logging.log("Ciphertext: " + str_data)
        self.widgets_dict["_Ciphertext"].set_text(str_data)
        self.widgets_dict["Ciphertext"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt(self, str_data):
        self.logging.log("Plaintext:  " + str_data)
        self.widgets_dict["_Plaintext"].set_text(str_data)
        self.logging.log("\n")

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
            if len(plaintext_list) % 16 != 0 or len(plaintext_list) == 0:
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
            self.widgets_dict["Plaintext"].set_text(TypeConvert.hex_list_to_str(plaintext_list))
            self.logging.log("Plaintext:  " + TypeConvert.hex_list_to_str(plaintext_list))
            plaintext_str = self.widgets_dict["Plaintext"].get_text()
            self.widgets_dict["Key"].set_text(TypeConvert.hex_list_to_str(key_list))
            self.logging.log("Key:        " + TypeConvert.hex_list_to_str(key_list))
            key_str = self.widgets_dict["Key"].get_text()
            # initial Block Mode thread
            # 选择分组模式，mode_select = 0时为ECB模式，mode_select = 1时为CBC模式
            if self.widgets_dict["ComboBox"].currentText() == "ECB":
                mode_selected = 0
            else:
                mode_selected = 1
            thread = Block_Mode.Thread(self, plaintext_str, key_str, mode_selected, 0, len(plaintext_list))
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.func_encrypt)
            # start Block Mode thread
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
            if len(ciphertext_list) % 16 != 0 or len(ciphertext_list) == 0:
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
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.hex_list_to_str(ciphertext_list))
            self.logging.log("Ciphertext:  " + TypeConvert.hex_list_to_str(ciphertext_list))
            ciphertext_str = self.widgets_dict["Ciphertext"].get_text()
            self.widgets_dict["Key"].set_text(TypeConvert.hex_list_to_str(key_list))
            self.logging.log("Key:        " + TypeConvert.hex_list_to_str(key_list))
            key_str = self.widgets_dict["Key"].get_text()
            # 选择分组模式，mode_select = 0时为ECB模式，mode_select = 1时为CBC模式
            if self.widgets_dict["ComboBox"].currentText() == "ECB":
                mode_selected = 0
            else:
                mode_selected = 1
            # 后续的操作有bug，方法在Block_Mode.py里，出现了NoneType也就是空数据
            thread = Block_Mode.Thread(self, ciphertext_str, key_str, mode_selected, 1, len(ciphertext_list))
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.func_decrypt)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def combox_changed(self):
        if self.widgets_dict["ComboBox"].currentIndex():
            self.widgets_dict["Ciphertext"].set_text("FF 61 06 68 B7 FF 38 F4 27 4B DB 68 A7 E9 44 47 "
                                                     "83 92 87 72 A0 08 EB A3 CE 86 D0 1D FA 34 C0 D1 "
                                                     "DB 91 CF 87 A0 A4 33 18 A6 90 86 D8 75 AF 35 CE "
                                                     "3A 91 44 E3 20 5F 8F 0C 45 AE FB 49 00 CA C9 20 "
                                                     "52 56 AC 42 2F 37 44 66 A3 A6 ED B9 22 56 C6 C3 "
                                                     "92 AE 65 E4 01 72 1F 99 4C 85 45 39 95 36 01 D8 "
                                                     "1C 66 F7 A3 DD BC 19 D9 6C C0 C5 82 0F 00 22 7C "
                                                     "D2 54 C5 A8 0C FA 42 40 E7 3B 69 90 BF C3 88 6C")
        else:
            self.widgets_dict["Ciphertext"].set_text("39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32 "
                                                     "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32")

if __name__ == '__main__':
    app = QApplication([])
    window = BlockModeWidget()
    app.exec_()