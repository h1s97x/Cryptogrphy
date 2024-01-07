from PyQt5.QtWidgets import QApplication

from PublicKeyCryptography import ElGamal
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert

class ElGamalWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("ElGamal Encryption")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Initialization",
                  plain_text_edits=[PlainTextEdit(id="p", label="p (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="α", label="α (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="x", label="x (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="y", label="y (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="m", label="m (Hex)", default_text=""),
                                    ],
                  buttons=[
                      Button(id="RandomReset", name="Random Reset", clicked_function=self.computer_generate),
                      Button(id="Clean", name="Clean", clicked_function=self.clean_parameters)
                  ]),

            Group(name="Encryption",
                  plain_text_edits=[PlainTextEdit(id="C1", label="C1 (Hex)", default_text=""),
                                    PlainTextEdit(id="C2", label="C2 (Hex)", default_text=""),
                                    ],
                  buttons=[
                      Button(id="Encrypt (PC)", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.clean_encrypt),
                  ]),
            Group(name="Decryption",
                  plain_text_edits=[PlainTextEdit(id="_m", label="m (Hex)", default_text=""),
                                    ],
                  buttons=[
                      Button(id="Decrypt (PC)", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.clean_decrypt),
                  ])
        ]

        self.render()
        self.logging.log("ElGamal algorithm has been imported.\n")

    def computer_generate(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Generate parameters on your computer.")
            thread = ElGamal.Thread(self, mode=0)
            thread.final_result.connect(self.set_parameters)
            # start thread
            thread.start()
        except Exception as e:
            self.logging.log(e)

    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            p = self.widgets_dict["p"].get_text()
            a = self.widgets_dict["α"].get_text()
            y = self.widgets_dict["y"].get_text()
            m = self.widgets_dict["m"].get_text()

            if p == '' or a == '' or y == '' or m == '':
                self.logging.log('Please generate parameters first.\n')
                self.pop_message_box("Please generate parameters first.\n")
                return

            if self.m_is_illegal():
                return

            m_value = TypeConvert.str_to_int(m)
            a_value = TypeConvert.str_to_int(a)
            y_value = TypeConvert.str_to_int(y)
            p_value = TypeConvert.str_to_int(p)

            thread = ElGamal.Thread(self, mode=2, p=p_value, a=a_value, y=y_value, m=m_value)
            thread.C1_C2.connect(self.set_C1C2)
            # start thread
            thread.start()
        except Exception as e:
            self.logging.log(e)

    def computer_decrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Decrypt on your computer.")
            C1 = self.widgets_dict["C1"].get_text()
            C2 = self.widgets_dict["C2"].get_text()
            x = self.widgets_dict["x"].get_text()
            p = self.widgets_dict["p"].get_text()

            if p == '' or x == '':
                self.logging.log('Please generate parameters first.\n')
                self.pop_message_box("Please generate parameters first.\n")
                return

            if C1 == '' or C2 == '':
                self.logging.log('Please generate C1 and C2.\n')
                self.pop_message_box("Please generate C1 and C2.\n")
                return

            C1_value = TypeConvert.str_to_int(C1)
            C2_value = TypeConvert.str_to_int(C2)
            XA_value = TypeConvert.str_to_int(x)
            p_value = TypeConvert.str_to_int(p)
            if C1_value is None or C2_value is None or XA_value is None or p_value is None:
                self.logging.log("Input data contains characters that do not meet the requirements.\n")
                self.pop_message_box("Input data contains characters that do not meet the requirements.\n")
                return

            thread = ElGamal.Thread(self, mode=1, C1=C1_value, C2=C2_value, x=XA_value, p=p_value)
            thread.M_result.connect(self.set_m)
            # start thread
            thread.start()
        except Exception as e:
            self.logging.log(e)

    def set_parameters(self, p, a, x, y, m):
        self.logging.log("p:                      " + p)
        self.widgets_dict["p"].set_text(p)
        self.logging.log("α:                  " + a)
        self.widgets_dict["α"].set_text(a)
        self.logging.log("x:                  " + x)
        self.widgets_dict["x"].set_text(x)
        self.logging.log("y:                  " + y)
        self.widgets_dict["y"].set_text(y)
        self.logging.log("m:                 " + m + '\n')
        self.widgets_dict["m"].set_text(m)

    @staticmethod
    def compare(list_p, list_m):
        for i in range(len(list_p)):
            if list_p[i] == list_m[i]:
                continue
            elif list_p[i] > list_m[i]:
                return 1
            else:
                return 0

    def m_is_illegal(self):
        p = self.widgets_dict["p"].get_text()
        m = self.widgets_dict["m"].get_text()
        if not self.error_check_str_to_hex_list(p, 'p'):
            return
        if not self.error_check_str_to_hex_list(m, 'm'):
            return
        p = TypeConvert.str_to_hex_list(p)
        m = TypeConvert.str_to_hex_list(m)

        if len(m) < 128:
            temp = []
            for i in range(128 - len(m)):
                temp.append(0)
            temp.extend(m)
            m = temp

        self.widgets_dict["m"].set_text(TypeConvert.hex_list_to_str(m))
        if not self.compare(p, m):
            self.logging.log('m should be less than p.\n')
            self.pop_message_box("m should be less than p.\n")
            return 1
        return 0

    def set_m(self, m):
        self.logging.log("m:                      " + m + '\n')
        self.widgets_dict["_m"].set_text(m)

    def set_C1C2(self, C1, C2):
        self.logging.log("C1:                      " + C1)
        self.widgets_dict["C1"].set_text(C1)
        self.logging.log("C2:                      " + C2 + '\n')
        self.widgets_dict["C2"].set_text(C2)

    def clean_parameters(self):
        self.widgets_dict["p"].set_text("")
        self.widgets_dict["α"].set_text("")
        self.widgets_dict["x"].set_text("")
        self.widgets_dict["y"].set_text("")
        self.widgets_dict["m"].set_text("")

    def clean_decrypt(self):
        self.widgets_dict["_m"].set_text("")

    def clean_encrypt(self):
        self.widgets_dict["C1"].set_text("")
        self.widgets_dict["C2"].set_text("")

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
    window = ElGamalWidget()
    app.exec_()
