from PyQt5.QtWidgets import QApplication

from Hash.AES_CBC_MAC import AES_CBC_MAC
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert

class AES_CBC_MACWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("AES-CBC-MAC")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="AES-CBC-MAC Hash",
                  plain_text_edits=[PlainTextEdit(id="Message", label="Message (Hex)",
                                                  default_text="32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "
                                                               "32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 "),
                                    PlainTextEdit(id="Key", label="Key (Hex)",
                                                  default_text="2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C "),
                                    PlainTextEdit(id="Hash", label="Hash (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerHash", name="Hash (PC)", clicked_function=self.computer_hash),
                      Button(id="CleanHash", name="Clean", clicked_function=self.hash_clean)
                  ]),
        ]
        self.render()
        self.logging.log("AES-CBC-MAC algorithm has been imported.\n")

    # hash on computer
    def computer_hash(self):
        try:
            # print the login information to main logging widget
            self.logging.log("HMac-Hash on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Message"].get_text(), 'Message'):
                return
            message_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Message"].get_text()))
            if message_len == 0 or message_len % 16 != 0:
                self.logging.log(ErrorType.LengthError.value + "Message length must be a multiple of 16.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Message length must be a multiple of 16.")
                return

            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return
            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len != 16:
                self.logging.log(ErrorType.LengthError.value + "Message length must be 16.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Message length must be 16.")
                return
            # format input
            message = TypeConvert.str_to_int(self.widgets_dict["Message"].get_text())
            self.widgets_dict["Message"].set_text(TypeConvert.int_to_str(message, message_len))
            self.logging.log("Message:     " + self.widgets_dict["Message"].get_text())
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))
            self.logging.log("Key    :     " + self.widgets_dict["Key"].get_text())

            # initial Hash thread
            thread = AES_CBC_MAC.Thread(self, message, message_len, self.widgets_dict["Key"].get_text())
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_hash)

            # start Hash thread
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_hash(self, string):
        self.widgets_dict["Hash"].set_text(string)
        self.logging.log("Hash:        " + string)
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
    window = AES_CBC_MACWidget()
    app.exec_()
