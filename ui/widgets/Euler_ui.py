from PyQt5.QtWidgets import QApplication

from core.algorithms.mathematical.Euclidean import Thread as Euclidean
from core.algorithms.mathematical.Euler import EulerFunctionThread, EulerTheoremThread
from ui.main_window import Button, PlainTextEdit, Group, ErrorType, KeyGroup, Key
from ui.main_window import CryptographyWidget


class EulerWidget(CryptographyWidget):
    def __init__(self):
        super().__init__()
        self.menuBar().setHidden(True)
        self.setWindowTitle("Euler Theorem")
        
        self.groups_config = [
            KeyGroup(
                name="Parameters",
                key_edit=[
                    Key(id="a", label="a (Int)", default_text="7", enabled=True),
                    Key(id="n", label="n (Int)", default_text="29", enabled=True),
                    Key(id="m", label="m (Int)", default_text="10", enabled=True)
                ],
                combo_box=[],
                buttons=[]
            ),
            Group(
                name="Results",
                plain_text_edits=[
                    PlainTextEdit(id="phi_m", label="φ(m)", default_text="", read_only=True),
                    PlainTextEdit(id="result", label="a^n(mod m)", default_text="", read_only=True)
                ],
                buttons=[
                    Button(id="phi", name="Calculate φ(m)", clicked_function=self.phi),
                    Button(id="mod", name="Calculate mod", clicked_function=self.calculate),
                    Button(id="Clean", name="Clean", clicked_function=self.clean)
                ]
            )
        ]

        self.render()
        self.log_message("Euler theorem has been imported.\n")

    def func_mod(self, str_data: str):
        self.log_message("Result is: " + str_data)
        self.widgets_dict["result"].set_text(str_data)
        self.log_message("\n")

    def func_phi(self, str_data: str):
        self.log_message("φ(m) is: " + str_data)
        self.widgets_dict["phi_m"].set_text(str_data)
        self.log_message("\n")

    def phi(self):
        try:
            self.log_message("Perform Euler function on your computer.")
            m = self.widgets_dict["m"].text()
            if not str(m).isdigit() or str(m) == "0":
                self.log_message(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            self.log_message("m:   " + m)
            m = int(m)
            thread = EulerFunctionThread(self, m)
            thread.final_result.connect(self.func_phi)
            thread.start()
        except Exception as e:
            self.logging_error(e)

    # encrypt on computer
    def calculate(self):
        try:
            # print the login information to main logging widget
            self.log_message("Perform Euler theorem on your computer.")
            a = self.widgets_dict["a"].text()
            if not str(a).isdigit() or str(a) == "0":
                self.log_message(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            n = self.widgets_dict["n"].text()
            if not str(n).isdigit() or str(n) == "0":
                self.log_message(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return
            m = self.widgets_dict["m"].text()
            if not str(m).isdigit() or str(m) == "0":
                self.log_message(ErrorType.NotMeetRequirementError.value)
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                self.widgets_dict["phi_m"].set_text("")
                return

            self.log_message("a:   " + a)
            self.log_message("n:   " + n)
            self.log_message("m:   " + m)
            a = int(a)
            n = int(n)
            m = int(m)
            phi_m = EulerFunctionThread.euler_phi(m)
            self.widgets_dict["phi_m"].set_text(str(phi_m))
            self.log_message("φ(m):" + str(phi_m))
            if Euclidean.Thread.gcd(a, m) != 1:
                result = self.warning_message_box("gcd(a,m) not equals 1! Maybe need a lot of time to calculating")
                if result == 1024:  # while OK
                    flag = 0
                else:
                    self.log_message("Calculate cancel")
                    self.log_message("\n")
                    return
            else:
                flag = 1
            thread = EulerTheoremThread(self, a, n, m, phi_m, flag)
            thread.print_final_result.connect(self.func_mod)
            thread.start()
        except Exception as e:
            self.logging_error(e)

    # clean widget text
    def clean(self):
        self.widgets_dict["phi_m"].set_text("")
        self.widgets_dict["result"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = EulerWidget()
    app.exec_()