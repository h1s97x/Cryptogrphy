from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from PublicKeyCryptography import SM2
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class SM2Widget(CryptographyWidget):
    key = None
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("SM2 Encryption")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[
                      PlainTextEdit(id="d", label="d (Hex)",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="P", label="P (Hex)",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="k", label="k (Hex)",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Generatekey", name="Generate Key (PC)", clicked_function=self.generate_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.key_text_clean)
                  ]),
            Group(name="Encryption",
                  plain_text_edits=[
                      PlainTextEdit(id="Message", label="Message",
                                    default_text="encryption standard"),
                      PlainTextEdit(id="Ciphertext", label="Ciphertext",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_text_clean),
                  ]),

            Group(name="Decryption",
                  plain_text_edits=[
                      PlainTextEdit(id="_Ciphertext", label="Ciphertext",
                                    default_text=""),
                      PlainTextEdit(id="Plaintext", label="Plaintext",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Decrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_text_clean)
                  ]),
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
        self.logging.log("SM2 algorithm has been imported.\n")
        self.d = None
        self.P = None
        self.k = None

    # generate key
    def generate_key(self):
        try:
            thread = SM2.SM2EncryptKeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_key(self, d, P, k):
        self.d = d
        self.P = P
        self.k = k
        self.logging.log("Generate key completes.")
        self.logging.log("d: {}".format(d))
        self.logging.log("P: {}".format(P))
        self.logging.log("k: {}\n".format(k))
        self.widgets_dict["d"].set_text(d)
        self.widgets_dict["P"].set_text(P)
        self.widgets_dict["k"].set_text(k)

    # clean widget text
    def encrypt_text_clean(self):
        # self.widgets_dict["Message"].set_text("")
        self.widgets_dict["Ciphertext"].set_text("")

    # clean widget text
    def decrypt_text_clean(self):
        # self.widgets_dict["_Ciphertext"].set_text("")
        self.widgets_dict["Plaintext"].set_text("")

    def key_text_clean(self):
        self.widgets_dict["d"].set_text("")
        self.widgets_dict["P"].set_text("")
        self.widgets_dict["k"].set_text("")
        self.key = None

    def computer_encrypt(self):
        try:
            d = self.widgets_dict["d"].get_text().strip()
            P = self.widgets_dict["P"].get_text().strip()
            k = self.widgets_dict["k"].get_text().strip()
            msg = self.widgets_dict["Message"].get_text().strip()
            if d != "" and P != "" and k != "" and msg != "":
                self.logging.log("SM2 encryption begins.\n")
                thread = SM2.SM2EncryptThread(self, d.replace(" ", ""), P.replace(" ", ""), k.replace(" ", ""), msg)
                thread.call_back.connect(self.set_up_ciphertext)
                thread.call_back.connect(self.widgets_dict["_Ciphertext"].set_text)
                thread.start()
                self.logging.log("d:         {}".format(d))
                self.logging.log("P:         {}".format(P))
                self.logging.log("k:         {}".format(k))
            elif d == "" or msg == "":
                self.pop_message_box("Please generate key first or input message.")
                self.logging.log("Please generate key first or input message.\n")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_ciphertext(self, ciphertext):
        self.logging.log("ciphertext:{}".format(ciphertext) + "\n")
        self.widgets_dict["Ciphertext"].set_text(ciphertext)

    def computer_decrypt(self):
        try:
            d = self.widgets_dict["d"].get_text().strip()
            P = self.widgets_dict["P"].get_text().strip()
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Ciphertext"].get_text().strip(), 'Ciphertext'):
                return
            ciphertext = self.widgets_dict["_Ciphertext"].get_text().strip()
            if d != "" and P != "" and ciphertext != "":
                self.logging.log("SM2 decryption begins.\n")
                thread = SM2.SM2DecryptThread(self, d.replace(" ", ""), P.replace(" ", ""), ciphertext.replace(" ", ""))
                thread.call_back.connect(self.set_up_plaintext)
                thread.start()
                self.logging.log("d:         {}".format(d))
                self.logging.log("P:         {}".format(P))
                self.logging.log("ciphertext:{}".format(ciphertext))
            elif d == '' or ciphertext == '':
                self.pop_message_box("Please generate key first or input ciphertext.")
                self.logging.log("Please generate key first or input ciphertext.\n")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_plaintext(self, plaintext):
        self.logging.log("plaintext: {}".format(plaintext) + "\n")
        self.widgets_dict["Plaintext"].set_text(plaintext)

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
    window = SM2Widget()
    app.exec_()
