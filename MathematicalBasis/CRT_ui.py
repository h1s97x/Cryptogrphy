from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from MathematicalBasis import Euclidean
from MathematicalBasis import CRT
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert


class CRTWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("CRT")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="",
                  plain_text_edits=[PlainTextEdit(id="a1", label="a1 (Int)", default_text="2"),
                                    PlainTextEdit(id="a2", label="a2 (Int)", default_text="3"),
                                    PlainTextEdit(id="a3", label="a3 (Int)", default_text="2"),
                                    PlainTextEdit(id="m1", label="m1 (Int)", default_text="3"),
                                    PlainTextEdit(id="m2", label="m2 (Int)", default_text="5"),
                                    PlainTextEdit(id="m3", label="m3 (Int)", default_text="7"),
                                    PlainTextEdit(id="result", label="Result", default_text="", read_only=True)],
                  buttons=[
                      Button(id="Solve", name="Solve", clicked_function=self.solve),
                      Button(id="Clean", name="Clean", clicked_function=self.clean)
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
        self.logging.log("Chinese remainder theorem has been imported.\n")

    def func(self, str_data: str):
        self.logging.log("Answer is: " + str_data)
        self.widgets_dict["result"].set_text(str_data)
        self.logging.log("\n")

    # encrypt on computer
    def solve(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Perform Chinese remainder theorem on your computer.")
            a1 = self.widgets_dict["a1"].get_text()
            if not str(a1).isdigit() or str(a1) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            a2 = self.widgets_dict["a2"].get_text()
            if not str(a2).isdigit() or str(a2) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            a3 = self.widgets_dict["a3"].get_text()
            if not str(a3).isdigit() or str(a3) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return

            m1 = self.widgets_dict["m1"].get_text()
            if not str(m1).isdigit() or str(m1) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            m2 = self.widgets_dict["m2"].get_text()
            if not str(m2).isdigit() or str(m2) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            m3 = self.widgets_dict["m3"].get_text()
            if not str(m3).isdigit() or str(m3) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            m1 = int(m1)
            m2 = int(m2)
            m3 = int(m3)
            if Euclidean.Thread.gcd(m1, m2) != 1:
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            if Euclidean.Thread.gcd(m2, m3) != 1:
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            if Euclidean.Thread.gcd(m3, m1) != 1:
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            self.logging.log("a1:  " + a1)
            self.logging.log("a2:  " + a2)
            self.logging.log("a3:  " + a3)
            self.logging.log("m1:  " + str(m1))
            self.logging.log("m2:  " + str(m2))
            self.logging.log("m3:  " + str(m3))
            a1 = int(a1)
            a2 = int(a2)
            a3 = int(a3)
            thread = CRT.Thread(self, [a1, a2, a3], [m1, m2, m3])
            thread.print_final_result.connect(self.func)
            thread.start()
        except Exception as e:
            self.logging.log(e)

    # clean widget text
    def clean(self):
        self.widgets_dict["result"].set_text("")


if __name__ == '__main__':
    app = QApplication([])
    window = CRTWidget()
    app.exec_()