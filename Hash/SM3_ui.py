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

        self.render()
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