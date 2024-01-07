from PyQt5.QtWidgets import QApplication

from StreamCipher import ZUC
from Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert

class ZUCWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        # set tabs widget configurations
        # link: link to the html file
        self.setWindowTitle("ZUC")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Key",
                  key_edit=[Key(enabled=True, id="Key", label="Key (Hex)",
                                        default_text="3D 4C 4B E9 6A 82 FD AE B5 8F 64 1D B1 7B 45 5B")],
                     combo_box=[],
                     buttons=[]
                     ),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="iv (Hex)",
                                                  default_text="84 31 9A A8 DE 69 15 CA 1F 6B DA 6B FB D8 C7 66"),
                                    PlainTextEdit(id="_Ciphertext", label="Key_stream z1(Hex) : ",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="_Ciphertext2", label="Key_stream z2(Hex) : ",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ])
        ]

        self.render()
        self.logging.log("ZUC algorithm has been imported.\n")

    def set_print_ciphertext(self, string):
        self.widgets_dict["_Ciphertext"].set_text(string)
        self.logging.log("KeyStream: " + string)
        self.logging.log('\n')

    def set_print_plaintext(self, string):
        self.widgets_dict["_Plaintext"].set_text(string)
        self.logging.log("iv: " + string)
        self.logging.log('\n')

    def set_print_ciphertext1(self, str1):
        self.widgets_dict["_Ciphertext"].set_text(str1)
        self.logging.log("KeyStream z1 : " + str1)

    def set_print_ciphertext2(self, str2):
        self.widgets_dict["_Ciphertext2"].set_text(str2)
        self.logging.log("KeyStream z2 : " + str2)
        self.logging.log('\n')

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Key"].get_text(), 'Key'):
                return

            key_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Key"].get_text()))
            if key_len != 16:
                self.logging.log(ErrorType.LengthError.value + "Key length must be 16.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Key length must be 16.")
                return

            if not self.error_check_str_to_hex_list(self.widgets_dict["Plaintext"].get_text(), 'Plaintext'):
                return

            plaintext_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text()))
            if plaintext_len != 16:
                self.logging.log(ErrorType.LengthError.value + "Plaintext length must be 16.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plaintext length must be 16.")
                return

            # format input
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, plaintext_len))
            key = TypeConvert.str_to_int(self.widgets_dict["Key"].get_text())
            self.widgets_dict["Key"].set_text(TypeConvert.int_to_str(key, key_len))

            # get text from target widget
            # then convert str to int
            self.logging.log("Key: " + TypeConvert.int_to_str(key, key_len))
            self.logging.log("iv : " + TypeConvert.int_to_str(plaintext, plaintext_len))

            # initial ZUC thread
            thread = ZUC.Thread(self, plaintext, plaintext_len, key, key_len, 0)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            # thread._print_final_result.connect(self.set_print_ciphertext)
            thread.final_result1.connect(self.set_print_ciphertext1)
            thread.final_result2.connect(self.set_print_ciphertext2)
            # start ZUC thread
            thread.start()

        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')


    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")
        self.widgets_dict["_Ciphertext2"].set_text("")

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
    window = ZUCWidget()
    app.exec_()
