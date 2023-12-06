from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

import Hash.SHA256 as SHA2
from PublicKeyCryptography import ECDSA
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert


class ECDSAWidget(CryptographyWidget):
    key = None
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("ECDSA")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Key",
                  key_edit=[
                      Key(id="k", label="k", default_text="", read_only=True),
                      Key(id="K", label="K", default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="GenerateKey", name="Generate Key", clicked_function=self.generate_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.key_clean)
                  ],
                  combo_box=[]
                     ),
            Group(name="Message",
                  plain_text_edits=[
                      PlainTextEdit(id="Message", label="Message(str)", default_text="Message"),
                      PlainTextEdit(id="Hash", label="Hash", default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="ComputerHash", name="Hash", clicked_function=self.hash),
                      Button(id="HashClean", name="Clean", clicked_function=self.hash_clean)
                  ]),
            Group(name="Signature",
                  plain_text_edits=[
                      PlainTextEdit(id="HashCopy", label="Hash", default_text=""),
                      PlainTextEdit(id="Signature", label="Signature", default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Sign", name="Sign", clicked_function=self.computer_signature),
                      Button(id="SignatureClean", name="Clean", clicked_function=self.signature_clean)
                  ]),
            Group(name="Verify",
                  plain_text_edits=[
                      PlainTextEdit(id="SignatureCopy", label="Signature", default_text=""),
                      PlainTextEdit(id="MessageCopy", label="Message", default_text="Message"),
                      PlainTextEdit(id="Result", label="Result", default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Verify", name="Verify", clicked_function=self.computer_verify),
                      Button(id="ResultClean", name="Clean", clicked_function=self.clean)
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
        self.logging.log("ECDSA signature algorithm has been imported.\n")
        self.key = None

    def generate_key(self):
        try:
            thread = ECDSA.ECDSAKeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_key(self, pri_k, pub_k, key):
        self.logging.log("Generate key completes.")
        self.logging.log("k: {}".format(pri_k))
        self.logging.log("K: {}\n".format(pub_k))
        self.widgets_dict["k"].set_text(pri_k.strip())
        self.widgets_dict["K"].set_text(pub_k.strip())
        self.key = key

    def key_clean(self):
        self.widgets_dict["k"].set_text("")
        self.widgets_dict["K"].set_text("")
        self.key = None

    def hash(self):
        try:
            message = TypeConvert.str_to_int(self.widgets_dict["Message"].get_text().encode().hex())
            message_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Message"].get_text().encode().hex()))
            if message_len == 0:
                self.logging.log("Please input Message.\n")
                self.pop_message_box("Please input Message.")
                return
            thread = SHA2.Thread(self, message, message_len)
            thread.final_result.connect(self.set_hash)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_hash(self, string):
        self.widgets_dict["Hash"].set_text(string)
        self.widgets_dict["HashCopy"].set_text(string)
        self.logging.log("Hash:" + string)
        self.logging.log('\n')

    def hash_clean(self):
        self.widgets_dict["Hash"].set_text("")

    def computer_signature(self):
        try:
            pri_key = self.widgets_dict["k"].get_text()
            message = self.widgets_dict["Message"].get_text().encode()
            if pri_key == "":
                self.logging.log("Please generate key first.\n")
                self.pop_message_box("Please generate key first.")
                return
            if message is None:
                self.logging.log("Please input Message.\n")
                self.pop_message_box("Please input Message.")
                return
            hash_value_space_error = TypeConvert.str_to_hex_list(self.widgets_dict["HashCopy"].get_text())
            self.widgets_dict["HashCopy"].set_text(TypeConvert.hex_list_to_str(hash_value_space_error))
            thread = ECDSA.ECDSASignatureThread(self, message, self.key)
            thread.call_back.connect(self.set_signature)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def signature_clean(self):
        self.widgets_dict["Signature"].set_text("")

    def set_signature(self, string):
        self.widgets_dict["Signature"].set_text(string)
        self.widgets_dict["SignatureCopy"].set_text(string)
        self.logging.log("Signature:" + string)
        self.logging.log('\n')

    def computer_verify(self):
        try:
            message = self.widgets_dict["MessageCopy"].get_text().encode()
            signature_text = TypeConvert.str_to_int(self.widgets_dict["SignatureCopy"].get_text())
            signature = signature_text.to_bytes(64, byteorder='big', signed=False)
            if message == b'':
                self.logging.log("Please input Message.\n")
                self.pop_message_box("Please input Message.")
            if signature is None:
                self.logging.log("Please input Signature.\n")
                self.pop_message_box("Please input Signature.")
                return
            self.widgets_dict["SignatureCopy"].set_text(TypeConvert.int_to_str(signature_text, 64))
            thread = ECDSA.VerifySignatureThread(self, message, signature, self.key)
            thread.call_back.connect(self.set_message)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def clean(self):
        self.widgets_dict["Result"].set_text("")

    def set_message(self, text):
        self.widgets_dict["Result"].set_text(text)
        self.logging.log("Result:" + text)
        self.logging.log('\n')

if __name__ == '__main__':
    app = QApplication([])
    window = ECDSAWidget()
    app.exec_()
