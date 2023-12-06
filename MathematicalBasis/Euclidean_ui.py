from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from MathematicalBasis import Euclidean
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class EuclideanWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Euclidean")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="",
                  plain_text_edits=[PlainTextEdit(id="a", label="a (Int)", default_text="18"),
                                    PlainTextEdit(id="b", label="b (Int)", default_text="12"),
                                    PlainTextEdit(id="result", label="result", default_text="")],
                  buttons=[
                      Button(id="Gcd", name="Gcd", clicked_function=self.calculate),
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
        self.logging.log("Euclidean algorithm has been imported.\n")

    def func(self, str_data):
        self.logging.log("Greatest Common Divisor is: " + str_data)
        self.widgets_dict["result"].set_text(str_data)
        self.logging.log("\n")

    # encrypt on computer
    def calculate(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Perform Euclidean algorithm on your computer.")
            a = self.widgets_dict["a"].get_text()
            if not str(a).isdigit() or str(a) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            b = self.widgets_dict["b"].get_text()
            if not str(b).isdigit() or str(b) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            self.logging.log("a:  " + a)
            self.logging.log("b:  " + b)
            a = int(a)
            b = int(b)
            thread = Euclidean.Thread(self, a, b)
            thread.final_result.connect(self.func)
            thread.start()
        except Exception as e:
            self.logging.log(e)

    # clean widget text
    def clean(self):
        self.widgets_dict["a"].set_text("")
        self.widgets_dict["b"].set_text("")
        self.widgets_dict["result"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = EuclideanWidget()
    app.exec_()