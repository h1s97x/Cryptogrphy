from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from BlockCipher import DES
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class DESWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.widgets_dict = {}
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
        self.logging.log("DES algorithm has been imported.\n")

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
            self.logging.log("Encrypt on your computer.")

            if not self.error_check_str_to_hex_list(self.widgets_dict["Plaintext"].get_text(), 'Plaintext'):
                return
            plaintext_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text()))
            if plaintext_len != 8:
                self.logging.log(ErrorType.LengthError.value + "Plaintext length must be 8.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plaintext length must be 8.")
                return

            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            encryption_mode = self.widgets_dict["ComboBox"].currentIndex()  # 0-DES, 1-3Des
            if encryption_mode == 0:
                if key_len != 8:
                    self.logging.log(ErrorType.LengthError.value + "Key length must be 8.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 8.")
                    return
            else:
                if key_len != 24:
                    self.logging.log(ErrorType.LengthError.value + "Key length must be 8. Key length must be 24.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 24.")
                    return
            # format input
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, plaintext_len))
            self.logging.log("Plaintext:  " + self.widgets_dict["Plaintext"].get_text())
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            self.logging.log("Key:        " + self.widgets_dict["Key"].get_text())

            # initial DES thread
            thread = DES.Thread(self, plaintext, plaintext_len, key, key_len, 0, encryption_mode)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_ciphertext)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            # start html thread
            thread.start()

        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_ciphertext(self, string):
        self.widgets_dict["_Ciphertext"].set_text(string)
        self.logging.log("Ciphertext: " + string)
        self.logging.log('\n')

    # decrypt on computer
    def computer_decrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Decrypt on your computer.")

            if not self.error_check_str_to_hex_list(self.widgets_dict["Ciphertext"].get_text(), 'Ciphertext'):
                return
            cipher_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Ciphertext"].get_text()))
            if cipher_len != 8:
                self.logging.log(ErrorType.LengthError.value + "Ciphertext length must be 8.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Ciphertext length must be 8.")
                return

            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            encryption_mode = self.widgets_dict["ComboBox"].currentIndex()  # 0-DES, 1-3Des
            if encryption_mode == 0:
                if key_len != 8:
                    self.logging.log(ErrorType.LengthError.value + "Key length must be 8.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 8.")
                    return
            else:
                if key_len != 24:
                    self.logging.log(ErrorType.LengthError.value + "Key length must be 24.\n")
                    self.pop_message_box(ErrorType.LengthError.value + "Key length must be 24.")
                    return

            # format input
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, cipher_len))
            self.logging.log("Ciphertext: " + TypeConvert.int_to_str(ciphertext, cipher_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            self.logging.log("Key:        " + TypeConvert.int_to_str(key, key_len))

            thread = DES.Thread(self, ciphertext, cipher_len, key, key_len, 1, encryption_mode)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_plaintext)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_plaintext(self, string):
        self.widgets_dict["_Plaintext"].set_text(string)
        self.logging.log("Plaintext:  " + string)
        self.logging.log('\n')

    # clean widget int_data
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget int_data
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
    window = DESWidget()
    app.exec_()