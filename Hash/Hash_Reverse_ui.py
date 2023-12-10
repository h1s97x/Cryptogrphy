from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from Hash import Hash_Reverse
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class HashReverseWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Hash Reverse")
        # self.tabs_config = [IntroductionTab(link="file:///" + Path.MENU_DIRECTORY + "/CryptographicAlgorithm/CryptographicHashFunction/Hash_Reverse/html/index.html")]
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Hash Function",
                     key_edit=[],
                     buttons=[],
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select", items=["SHA1", "SHA256", "SHA3-256", "MD5", "SM3"], changed_function=self.combo_changed)]
                     ),
            Group(name="Hash Reverse",
                  plain_text_edits=[PlainTextEdit(id="Hash", label="Hash (Hex)", default_text="D7 80 DC 14 B5 8B 09 0F 5F EE FD 65 01 AF 15 35 4E 78 DC 2E"),
                                    PlainTextEdit(id="Message", label="Message (String)", default_text="", read_only=True)],
                  buttons=[
                      Button(id="Hash_Reverse", name="Hash Reverse", clicked_function=self.hash_reverse),
                      Button(id="Clean", name="Clean", clicked_function=self.hash_clean)
                  ]),
        ]
        self.render()
        self.logging.log("HashReverse algorithm has been imported.\n")
        # when combobox changed

    def combo_changed(self):
        if self.widgets_dict["ComboBox"].currentIndex() == 0:  # 自动获取当前索引值currentIndex()
            self.widgets_dict["Hash"].set_text("D7 80 DC 14 B5 8B 09 0F 5F EE FD 65 01 AF 15 35 4E 78 DC 2E")
        elif self.widgets_dict["ComboBox"].currentIndex() == 1:
            self.widgets_dict["Hash"].set_text("1E 6C 30 AB 91 D1 F1 D6 19 96 AE 17 BC 9A F1 CA 8B CD ED 8A 04 14 DE 79 25 8D C0 C5 2D 22 15 EE")
        elif self.widgets_dict["ComboBox"].currentIndex() == 2:
            self.widgets_dict["Hash"].set_text("89 6B 3F 21 B2 51 4E EA 93 C1 F7 CC 82 65 F8 83 2B 9A 34 67 2B 47 9C 4A E8 2A BB E1 0B C2 ED D9")
        elif self.widgets_dict["ComboBox"].currentIndex() == 3:
            self.widgets_dict["Hash"].set_text("A7 59 78 A7 A4 91 85 AD 06 38 43 76 5D 58 C4 D6")
        elif self.widgets_dict["ComboBox"].currentIndex() == 4:
            self.widgets_dict["Hash"].set_text("B3 CD 3E 9E 71 48 36 62 5C E5 20 A0 F1 77 3F 23 B7 C0 E3 9E 5A 4B 7B 72 E2 B1 49 4A 76 F6 D3 29")

    def hash_reverse(self):
        try:
            # print the login information to main logging widget
            self.logging.log("Hash Reverse on your computer.")
            if not self.error(self.widgets_dict["Hash"].get_text(), 'Hash'):
                return

            hash_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Hash"].get_text()))
            hash_number = self.widgets_dict["ComboBox"].currentIndex()
            if hash_len == 0:
                self.logging.log(ErrorType.LengthError.value + "The Hash length cannot be 0.\n")
                self.pop_message_box(ErrorType.LengthError.value + "The Hash length cannot be 0.")
                return
            elif ((hash_number == 1) | (hash_number == 2) | (hash_number == 4)) & (hash_len != 32):
                self.logging.log(ErrorType.LengthError.value + "The Hash length must be 32.\n")
                self.pop_message_box(ErrorType.LengthError.value + "The Hash length must be 32.")
                return
            elif (hash_number == 0) & (hash_len != 20):
                self.logging.log(ErrorType.LengthError.value + "The Hash length must be 20.\n")
                self.pop_message_box(ErrorType.LengthError.value + "The Hash length must be 20.")
                return
            elif (hash_number == 3) & (hash_len != 16):
                self.logging.log(ErrorType.LengthError.value + "The Hash length must be 16.\n")
                self.pop_message_box(ErrorType.LengthError.value + "The Hash length must be 16.")
                return
            hash_mode = self.widgets_dict["ComboBox"].currentText()
            # format input
            hash_result = TypeConvert.str_to_int(self.widgets_dict["Hash"].get_text())
            self.widgets_dict["Hash"].set_text(TypeConvert.int_to_str(hash_result, hash_len))

            # get text from target widget
            # then convert str to int
            self.logging.log("Hash: " + TypeConvert.int_to_str(hash_result, hash_len))
            self.logging.log("\n")
            # initial Hash Reverse thread
            thread = Hash_Reverse.Thread(self, self.widgets_dict["Hash"].get_text(), hash_mode)
            thread.final_result.connect(self.set_print_message)
            # start Hash Reverse thread
            thread.start()

        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_print_message(self, string):
        self.widgets_dict["Message"].set_text(string)
        self.logging.log("Message:    " + string)
        self.logging.log('\n')

    def hash_clean(self):
        self.widgets_dict["Message"].set_text("")

    def error(self, text: str, input_name: str) -> bool:
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
    window = HashReverseWidget()
    app.exec_()

