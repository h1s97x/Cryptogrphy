from PyQt5.QtWidgets import QApplication

from core.algorithms.hash.SHA3 import Thread as SHA3
from ui.main_window import Button, PlainTextEdit, KeyGroup, Group, ErrorType, ComboBox
from ui.main_window import CryptographyWidget


class SHA3Widget(CryptographyWidget):
    def __init__(self):
        super().__init__()
        self.menuBar().setHidden(True)
        self.setWindowTitle("SHA-3")        self.groups_config = [
            KeyGroup(name="",
                     key_edit=[],
                     buttons=[],
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                                         items=["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"],
                                         changed_function=self.combo_changed)]),

            Group(name="SHA-3 Hash",
                  plain_text_edits=[PlainTextEdit(id="Message", label="Message (Bin)",
                                                  default_text="1100 1"),
                                    PlainTextEdit(id="Hash", label="Hash (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerHash", name="Hash (Computer)", clicked_function=self.computer_hash),
                      Button(id="CleanHash", name="Clean", clicked_function=self.hash_clean)
                  ]),
        ]
        self.sha3_len = 224
        self.render()
        self.log_message("SHA-3 algorithm has been imported.\n")

        self.card_limit_len = {224: 1600 - 2 * 224 - 4,
                               256: 1600 - 2 * 256 - 4,
                               384: 1600 - 2 * 384 - 4,
                               512: 1600 - 2 * 512 - 4}

    # encrypt on computer
    def computer_hash(self):
        try:
            # print the login information to main logging widget
            self.log_message("Hash on your computer.")
            if not self.error_check_bin(self.widgets_dict["Message"].get_text().replace('\n', '').replace(' ', '').replace('\t', '').replace('\r', '')):
                return

            message_len = len(self.widgets_dict["Message"].get_text().replace('\n', '').replace(' ', '').replace('\t', '').replace('\r', ''))
            if message_len == 0:
                message = None
                self.widgets_dict["Message"].set_text('')
                self.log_message("Message: None")
            else:
                message = self.widgets_dict["Message"].get_text().replace('\n', '').replace(' ', '').replace('\t', '').replace('\r', '')
                self.widgets_dict["Message"].set_text(self._message_show_format(message))
                self.log_message("Message: " + message)

            # initial Sha_3 Hash thread
            thread = SHA3.Thread(self, message, self.sha3_len)
            # thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.final_result.connect(self.set_print_hash)
            # start Hash thread
            thread.start()
            # self.log_message("\n")
        except Exception as e:
            self.log_message('Error:' + str(e) + '\n')

    def set_print_hash(self, string):
        self.widgets_dict["Hash"].set_text(string)
        self.log_message("Hash:    " + string)
        self.log_message('\n')

    # clean widget text
    def hash_clean(self):
        self.widgets_dict["Hash"].set_text("")

    def error_check_bin(self, text: str) -> bool:
        if text == '':
            return True
        else:
            try:
                _ = int(text, 2)
                return True
            except Exception as e:
                self.log_message(ErrorType.NotMeetRequirementError.value + '\n')
                self.pop_message_box(ErrorType.NotMeetRequirementError.value)
                return False

    def combo_changed(self):
        if self.widgets_dict["ComboBox"].currentIndex() == 0:
            self.sha3_len = 224
        elif self.widgets_dict["ComboBox"].currentIndex() == 1:
            self.sha3_len = 256
        elif self.widgets_dict["ComboBox"].currentIndex() == 2:
            self.sha3_len = 384
        elif self.widgets_dict["ComboBox"].currentIndex() == 3:
            self.sha3_len = 512

    @staticmethod
    def _message_show_format(bin_text):
        count = 0
        for i in range(len(bin_text) // 4):
            bin_text = bin_text[:(i + 1) * 4 + count] + ' ' + bin_text[(i + 1) * 4 + count:]
            count += 1
        return bin_text
if __name__ == '__main__':
    app = QApplication([])
    window = SHA3Widget()
    app.exec_()