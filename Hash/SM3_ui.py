from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from Hash import SM3
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class SM3Widget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("SM3")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="SM3 Hash",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Message (Hex)",
                                                  default_text="61 62 63"),
                                    PlainTextEdit(id="_Ciphertext", label="Hash (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerHash", name="Hash (PC)", clicked_function=self.computer_hash),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
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
        self.logging.log("SM3 algorithm has been imported.\n")

    # encrypt on computer
    def computer_hash(self):
        try:
            # get text from target widget and print the login information to main logging widget and
            self.logging.log("Hash on computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Plaintext"].get_text(), 'Plaintext'):
                return
            plaintext = TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text())
            if plaintext is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Message\" input box.")
                self.logging.log("\n")
                return
            # format input
            self.widgets_dict["Plaintext"].set_text(TypeConvert.hex_list_to_str(plaintext))
            self.logging.log("Message:    " + TypeConvert.hex_list_to_str(plaintext))
            # initial SM3 thread
            thread = SM3.Thread(self, plaintext)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.widgets_dict["_Ciphertext"].set_text)
            thread.final_result.connect(self.print_result_to_logging)
            # start SM3 thread
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
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

    def print_result_to_logging(self, str_data):
        self.logging.log("Result:     " + str(str_data))
        self.logging.log("\n")

if __name__ == '__main__':
    app = QApplication([])
    window = SM3Widget()
    app.exec_()