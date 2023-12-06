from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from Hash import SHA3
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert


class SHA3Widget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("SHA-3")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="",
                     key_edit=[],
                     buttons=[],
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                                         items=["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"],
                                         changed_function=self.combo_changed)]),

            Group(name="SHA-3 Hash",
                  plain_text_edits=[PlainTextEdit(id="Message", label="Message (Bin)",
                                                  default_text="1100 1"),
                                    PlainTextEdit(id="Hash", label="Hash (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerHash", name="Hash (Computer)", clicked_function=self.computer_hash),
                      Button(id="CleanHash", name="Clean", clicked_function=self.hash_clean)
                  ]),
        ]
        self.sha3_len = 224
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
        self.logging.log("SHA-3 algorithm has been imported.\n")

        self.card_limit_len = {224: 1600 - 2 * 224 - 4,
                               256: 1600 - 2 * 256 - 4,
                               384: 1600 - 2 * 384 - 4,
                               512: 1600 - 2 * 512 - 4}

    # encrypt on computer
    def computer_hash(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Hash on your computer.")
            if not self.error_check_bin(self.widgets_dict["Message"].get_text().replace('\n', '').replace(' ', '').replace('\t', '').replace('\r', '')):
                return

            message_len = len(self.widgets_dict["Message"].get_text().replace('\n', '').replace(' ', '').replace('\t', '').replace('\r', ''))
            if message_len == 0:
                message = None
                self.widgets_dict["Message"].set_text('')
                self.logging.log("Message: None")
            else:
                message = self.widgets_dict["Message"].get_text().replace('\n', '').replace(' ', '').replace('\t', '').replace('\r', '')
                self.widgets_dict["Message"].set_text(self._message_show_format(message))
                self.logging.log("Message: " + message)

            # initial Sha_3 Hash thread
            thread = SHA3.Thread(self, message, self.sha3_len)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_hash)
            # start Hash thread
            thread.start()
            # self.logging.log("\n")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_hash(self, string):
        self.widgets_dict["Hash"].set_text(string)
        self.logging.log("Hash:    " + string)
        self.logging.log('\n')

    # clean widget text
    def hash_clean(self):
        self.widgets_dict["Hash"].set_text("")

    def error_check_bin(self, text: str) -> bool:
        if text == '':
            return True
        else:
            try:
                _ = int(text, 2)
                return True
            except Exception as e:
                self.logging.log(ErrorType.NotMeetRequirementError.value + '\n')
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return False

    def combo_changed(self):
        if self.widgets_dict["ComboBox"].currentIndex() == 0:
            self.sha3_len = 224
        elif self.widgets_dict["ComboBox"].currentIndex() == 1:
            self.sha3_len = 256
        elif self.widgets_dict["ComboBox"].currentIndex() == 2:
            self.sha3_len = 384
        elif self.widgets_dict["ComboBox"].currentIndex() == 3:
            self.sha3_len = 512

    @staticmethod
    def _message_show_format(bin_text):
        count = 0
        for i in range(len(bin_text) // 4):
            bin_text = bin_text[:(i + 1) * 4 + count] + ' ' + bin_text[(i + 1) * 4 + count:]
            count += 1
        return bin_text
if __name__ == '__main__':
    app = QApplication([])
    window = SHA3Widget()
    app.exec_()