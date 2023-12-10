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

        self.render()
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