from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from StreamCipher import SEAL
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class SEALWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("SEAL")
        self.PlainLen = int(128 / 8)
        self.KeyLen = int(160 / 8)
        self.widgets_dict = {}
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

        layout = QVBoxLayout()
        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        for group_config in self.groups_config:
            group_label = QLabel(group_config.name)
            layout.addWidget(group_label)

            if isinstance(group_config, KeyGroup):
                for edit in group_config.key_edit:
                    edit_label = QLabel(edit.label)
                    layout.addWidget(edit_label)

                    edit_text = edit.text
                    edit_widget = TextEdit(edit_text)  # 使用QLineEdit或其他适当的小部件替换此处的QLabel
                    layout.addWidget(edit_widget)

                    self.widgets_dict[edit.id] = edit_widget  # 将小部件与edit对象关联起来

                for combo in group_config.combo_box:
                    combo_label = QLabel(combo.label)
                    layout.addWidget(combo_label)

                    combo_items = combo.items
                    combo_widget = QComboBox()
                    combo_widget.addItems(combo_items)
                    layout.addWidget(combo_widget)

                    self.widgets_dict[combo.id] = combo_widget  # 将小部件与combo对象关联起来
                    combo_widget.currentIndexChanged.connect(combo.changed_function)  # 添加这一行以关联信号和槽函数

            if isinstance(group_config, Group):
                for plain_text_edit in group_config.plain_text_edits:
                    self.widgets_dict[plain_text_edit.id] = plain_text_edit
                    edit_label = QLabel(plain_text_edit.label)
                    layout.addWidget(edit_label)

                    edit_text = plain_text_edit.text
                    edit_widget = TextEdit(edit_text)
                    layout.addWidget(edit_widget)
                    self.widgets_dict[plain_text_edit.id] = edit_widget  # 将QTextEdit小部件与plain_text_edit对象关联起来

            for button in group_config.buttons:
                self.widgets_dict[button.id] = button
                button_widget = QPushButton(button.name)
                button_widget.clicked.connect(button.clicked_function)
                layout.addWidget(button_widget)

        layout.addWidget(self.logging.log_widget)

        self.setGeometry(300, 300, 500, 400)
        self.show()
        self.logging.log("SEAL algorithm has been imported.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()

            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            temp = len(key_list)
            if temp != self.KeyLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box." + str(temp))
                self.logging.log("\n")
                return
            plaintext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text())
            if plaintext_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            temp = len(plaintext_list)
            if temp != self.PlainLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            # get text from target widget
            # then convert str to int
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, self.PlainLen))
            self.logging.log("Plaintext:  " + TypeConvert.int_to_str(plaintext, self.PlainLen))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, self.KeyLen))
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, self.KeyLen))
            # initial AES thread
            thread = SEAL.Thread(self, plaintext, key, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Ciphertext"].set_text)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            # start AES thread
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    def print_result_to_logging(self, str_data):
        self.logging.log("Result:     " + str(str_data))
        self.logging.log("\n")

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            temp = len(key_list)
            if temp != self.KeyLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            ciphertext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text())
            if ciphertext_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            temp = len(ciphertext_list)
            if temp != self.PlainLen:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            # get text from target widget
            # then convert str to int
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, self.PlainLen))
            self.logging.log("Ciphertext: " + TypeConvert.int_to_str(ciphertext, self.PlainLen))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, self.KeyLen))
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, self.KeyLen))
            thread = SEAL.Thread(self, ciphertext, key, 1)
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

if __name__ == '__main__':
    app = QApplication([])
    window = SEALWidget()
    app.exec_()
