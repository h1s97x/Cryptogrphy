from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from MathematicalBasis import Euclidean
from MathematicalBasis import Euler
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class EulerWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Euler")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="",
                  plain_text_edits=[PlainTextEdit(id="a", label="a (Int)", default_text="7"),
                                    PlainTextEdit(id="n", label="n (Int)", default_text="29"),
                                    PlainTextEdit(id="m", label="m (Int)", default_text="10"),
                                    PlainTextEdit(id="phi_m", label="φ(m)", default_text="", read_only=True),
                                    PlainTextEdit(id="result", label="a^n(mod m)", default_text="", read_only=True)],
                  buttons=[
                      Button(id="phi", name="φ(m)", clicked_function=self.phi),
                      Button(id="mod", name="mod", clicked_function=self.calculate),
                      Button(id="Clean", name="Clean", clicked_function=self.clean)]
                  ),
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
        self.logging.log("Euler theorem has been imported.\n")

    def func_mod(self, str_data: str):
        self.logging.log("Result is: " + str_data)
        self.widgets_dict["result"].set_text(str_data)
        self.logging.log("\n")

    def func_phi(self, str_data: str):
        self.logging.log("φ(m) is: " + str_data)
        self.widgets_dict["phi_m"].set_text(str_data)
        self.logging.log("\n")

    def phi(self):
        try:
            self.logging.log("Perform Euler function on your computer.")
            m = self.widgets_dict["m"].get_text()
            if not str(m).isdigit() or str(m) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            self.logging.log("m:   " + m)
            m = int(m)
            thread = Euler.EulerFunctionThread(self, m)
            thread.final_result.connect(self.func_phi)
            thread.start()
        except Exception as e:
            self.logging.log(e)

    # encrypt on computer
    def calculate(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Perform Euler theorem on your computer.")
            a = self.widgets_dict["a"].get_text()
            if not str(a).isdigit() or str(a) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            n = self.widgets_dict["n"].get_text()
            if not str(n).isdigit() or str(n) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            m = self.widgets_dict["m"].get_text()
            if not str(m).isdigit() or str(m) == "0":
                self.logging.log(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                self.widgets_dict["phi_m"].set_text("")
                return

            self.logging.log("a:   " + a)
            self.logging.log("n:   " + n)
            self.logging.log("m:   " + m)
            a = int(a)
            n = int(n)
            m = int(m)
            phi_m = Euler.EulerFunctionThread.euler_phi(m)
            self.widgets_dict["phi_m"].set_text(str(phi_m))
            self.logging.log("φ(m):" + str(phi_m))
            if Euclidean.Thread.gcd(a, m) != 1:
                result = self.warning_message_box("gcd(a,m) not equals 1! Maybe need a lot of time to calculating")
                if result == 1024:  # while OK
                    flag = 0
                else:
                    self.logging.log("Calculate cancel")
                    self.logging.log("\n")
                    return
            else:
                flag = 1
            thread = Euler.EulerTheoremThread(self, a, n, m, phi_m, flag)
            thread.print_final_result.connect(self.func_mod)
            thread.start()
        except Exception as e:
            self.logging.log(e)

    # clean widget text
    def clean(self):
        self.widgets_dict["phi_m"].set_text("")
        self.widgets_dict["result"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = EulerWidget()
    app.exec_()