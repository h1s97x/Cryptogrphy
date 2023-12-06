from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from Hash import HMAC_MD5
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert


class MD5_HMACWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("HMAC-MD5")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="HMac-MD5 Hash",
                  plain_text_edits=[PlainTextEdit(id="Message", label="Message (Hex)",
                                                  default_text="61 62 63"),
                                    PlainTextEdit(id="Key", label="Key (Hex)",
                                                  default_text="61 62 63"),
                                    PlainTextEdit(id="Hash", label="Hash (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerHash", name="Hash (PC)", clicked_function=self.computer_hmac_hash),
                      Button(id="CleanHash", name="Clean", clicked_function=self.hash_clean)
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
        self.logging.log("HMAC-MD5 algorithm has been imported.\n")

    # encrypt on computer
    def computer_hmac_hash(self):
        try:
            # print the login information to main logging widget
            self.logging.log("HMAC-Hash on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Message"].get_text(), 'Message'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            message_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Message"].get_text()))
            if message_len == 0:
                self.logging.log(ErrorType.LengthError.value + "You should check the \"Message\" input box.\n")
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Message\" input box.")
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len == 0:
                self.logging.log(ErrorType.LengthError.value + "You should check the \"Key\" input box.\n")
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key\" input box.")
                return
            # format input
            message = TypeConvert.str_to_int(self.widgets_dict["Message"].get_text())
            self.widgets_dict["Message"].set_text(TypeConvert.int_to_str(message, message_len))
            self.logging.log("Message:     " + TypeConvert.int_to_str(message, message_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            self.logging.log("Key    :     " + TypeConvert.int_to_str(key, key_len))

            # initial HMAC Md5 Hash thread
            thread = HMAC_MD5.Thread(self, message, message_len, key, key_len)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_hash)

            # start Hash thread
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_hash(self, string):
        self.widgets_dict["Hash"].set_text(string)
        self.logging.log("Hash:        " + string)
        self.logging.log('\n')

    # clean widget text
    def hash_clean(self):
        self.widgets_dict["Hash"].set_text("")

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
    window = MD5_HMACWidget()
    app.exec_()