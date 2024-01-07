from PyQt5.QtWidgets import QApplication

from Hash.MD5 import MD5
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert


class MD5Widget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("MD5")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="MD5 Hash",
                  plain_text_edits=[PlainTextEdit(id="Message", label="Message (Hex)",
                                                  default_text="61 62 63"),
                                    PlainTextEdit(id="Hash", label="Hash (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerHash", name="Hash (PC)", clicked_function=self.computer_hash),
                      Button(id="CleanHash", name="Clean", clicked_function=self.hash_clean)
                  ]),
        ]

        self.render()
        self.logging.log("MD5 algorithm has been imported.\n")

    # encrypt on computer
    def computer_hash(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Hash on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Message"].get_text(), 'Message'):
                return
            message_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Message"].get_text()))
            if message_len == 0:
                self.logging.log(ErrorType.LengthError.value + "You should check the \"Message\" input box.\n")
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Message\" input box.")
                return
            # format input
            message = TypeConvert.str_to_int(self.widgets_dict["Message"].get_text())
            self.widgets_dict["Message"].set_text(TypeConvert.int_to_str(message, message_len))
            self.logging.log("Message:     " + TypeConvert.int_to_str(message, message_len))

            # initial Md5 Hash thread
            thread = MD5.Thread(self, message, message_len)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_hash)

            # start Hash thread
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_hash(self, string):
        self.widgets_dict["Hash"].set_text(string)
        self.logging.log("Hash:       " + string)
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
    window = MD5Widget()
    app.exec_()