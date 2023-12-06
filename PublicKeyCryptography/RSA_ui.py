from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from PublicKeyCryptography import RSA
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class RSAWidget(CryptographyWidget):
    key = None
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("RSA")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[
                      PlainTextEdit(id="p", label="p",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="q", label="q",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="N", label="N",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="e", label="e",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="d", label="d",
                                    default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Generatekey", name="Generate Key (PC)", clicked_function=self.generate_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.key_clean)
                  ]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 "
                                                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00"),
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
        self.logging.log("RSA algorithm has been imported.\n")

    # generate key
    def generate_key(self):
        try:
            thread = RSA.KeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log(e)

    def set_up_key(self, key):
        self.key = key
        private_key = key[1]
        self.logging.log("Generate key completes.")
        self.logging.log("p: {}".format(TypeConvert.int_to_str(private_key.p, 64)))
        self.logging.log("q: {}".format(TypeConvert.int_to_str(private_key.q, 64)))
        self.logging.log("N: {}".format(TypeConvert.int_to_str(private_key.n, 128)))
        self.logging.log("e: {}".format(TypeConvert.int_to_str(private_key.e, 4)))
        self.logging.log("d: {}\n".format(TypeConvert.int_to_str(private_key.d, 128)))
        self.widgets_dict["p"].set_text(TypeConvert.int_to_str(private_key.p, 64))
        self.widgets_dict["q"].set_text(TypeConvert.int_to_str(private_key.q, 64))
        self.widgets_dict["N"].set_text(TypeConvert.int_to_str(private_key.n, 128))
        self.widgets_dict["e"].set_text(TypeConvert.int_to_str(private_key.e, 4))
        self.widgets_dict["d"].set_text(TypeConvert.int_to_str(private_key.d, 128))

    # encrypt on computer
    def computer_encrypt(self):
        try:
            self.encrypt_clean()
            if self.key is None:
                self.logging.log("Please generate a public-private key pair first.\n")
                self.pop_message_box("Please generate a public-private key pair first.")
                return

            _plaintext = self.widgets_dict["Plaintext"].get_text()
            if not self.error_check_str_to_hex_list(_plaintext, 'Plaintext'):
                return
            plaintext_list = TypeConvert.str_to_hex_list(_plaintext)

            if plaintext_list is None:
                return

            if len(plaintext_list) != 128:
                self.logging.log("The length of input text should be 128 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(len(plaintext_list)) + " now.\n")
                self.pop_message_box("The length of input text should be 128 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(len(plaintext_list)) + " now.")
                return

            # format
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, 128))
            if plaintext >= self.key[0].n:
                self.logging.log("The plaintext is too long for n.")
                self.pop_message_box("The plaintext is too long for n.")
                return
            # get values
            _plaintext = self.widgets_dict["Plaintext"].get_text()
            plaintext_list = TypeConvert.str_to_hex_list(_plaintext)

            plaintext_bytes = bytes(plaintext_list)
            thread = RSA.RsaThread(parent=self, input_bytes=plaintext_bytes, key=self.key, encrypt_selected=0)
            thread.call_back.connect(self.widgets_dict["_Ciphertext"].set_text)
            thread.call_back.connect(self.widgets_dict["Ciphertext"].set_text)
            thread.call_back.connect(self.print_result_to_logging)
            # start AES thread
            self.logging.log("Encrypt on your computer.")
            etext = TypeConvert.str_to_int(self.widgets_dict["e"].get_text())
            ntext = TypeConvert.str_to_int(self.widgets_dict["N"].get_text())
            self.logging.log("Plaintext:  " + TypeConvert.int_to_str(plaintext, 128))
            self.logging.log("e:          " + TypeConvert.int_to_str(etext, 4))
            self.logging.log("N:          " + TypeConvert.int_to_str(ntext, 128))
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def print_result_to_logging(self, str_data):
        self.logging.log("Result:     " + str(str_data))
        self.logging.log("\n")

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.decrypt_clean()
            if self.key is None:
                self.logging.log("Please generate a public-private key pair first.\n")
                self.pop_message_box("Please generate a public-private key pair first.\n")
                return

            _plaintext = self.widgets_dict["Ciphertext"].get_text()
            if not self.error_check_str_to_hex_list(_plaintext, 'Ciphertext'):
                return
            plaintext_list = TypeConvert.str_to_hex_list(_plaintext)
            if plaintext_list is None:
                return

            if len(plaintext_list) != 128:
                self.logging.log("The length of input text should be 128 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(len(plaintext_list)) + " now.\n")
                self.pop_message_box("The length of input text should be 128 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(len(plaintext_list)) + " now.")
                return

            # format
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["Ciphertext"].get_text())
            self.widgets_dict["Ciphertext"].set_text(TypeConvert.int_to_str(ciphertext, 128))
            # get values
            _plaintext = self.widgets_dict["Ciphertext"].get_text()
            plaintext_list = TypeConvert.str_to_hex_list(_plaintext)

            plaintext_bytes = bytes(plaintext_list)
            thread = RSA.RsaThread(parent=self, input_bytes=plaintext_bytes, key=self.key, encrypt_selected=1)
            thread.call_back.connect(self.widgets_dict["_Plaintext"].set_text)
            thread.call_back.connect(self.print_result_to_logging)
            # start RSA thread
            self.logging.log("Decrypt on your computer.")
            # etext= TypeConvert.str_to_int(self.widgets_dict["e"].get_text())
            # ntext= TypeConvert.str_to_int(self.widgets_dict["N"].get_text())
            dtext = TypeConvert.str_to_int(self.widgets_dict["d"].get_text())
            self.logging.log("Ciphertext: " + TypeConvert.int_to_str(ciphertext, 128))
            self.logging.log("d:          " + TypeConvert.int_to_str(dtext, 128))
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def key_clean(self):
        self.widgets_dict["N"].set_text("")
        self.widgets_dict["e"].set_text("")
        self.widgets_dict["d"].set_text("")
        self.widgets_dict["p"].set_text("")
        self.widgets_dict["q"].set_text("")
        self.key = None

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
    window = RSAWidget()
    app.exec_()
