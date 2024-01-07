import os
from PyQt5.QtWidgets import QApplication

from ClassicCrypto.Frequency_Analysis import Frequency_Analysis
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import Path

class FAWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Frequency Analysis")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="File Import",
                  plain_text_edits=[PlainTextEdit(id="Filepath", label="File Path",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ImportFile", name="Import File", clicked_function=self.import_file),
                      Button(id="Clean_import", name="Clean", clicked_function=self.encrypt_clean_import)
                  ]),
            Group(name="Single Letter",
                  plain_text_edits=[],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.attack)
                  ]),
            Group(name="Multi Letter",
                  plain_text_edits=[],
                  buttons=[
                      Button(id="ComputerDecrypt_multi", name="Decrypt Multi (PC)", clicked_function=self.attack_multi)
                  ])
        ]
        self.render()
        self.logging.log("Frequency Analysis Attack has been imported.\n")

    def logging_decrypt_multi(self, str_data):
        self.logging.log(str_data)
        self.logging.log("\n")

    def import_file(self):
        try:
            directory = Path.MENU_DIRECTORY
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", directory)
            self.widgets_dict["Filepath"].set_text(file_path)
        except Exception as e:
            self.logging.log_error(e)
        self.logging.log("File imported successfully.\n")

    def attack(self):
        try:
            self.logging.log("Decrypt on your computer.")
            text = self.widgets_dict["Filepath"].get_text()
            if not os.path.exists(text):
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"FilePath\" box.")
                self.logging.log("\n")
                return
            if os.stat(str(text)).st_size > 2048 * 1024:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " In order to ensure the decryption speed, the file size should be within 2M.")
                self.logging.log("\n")
                return
            if text == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"FilePath\" box.")
                self.logging.log("\n")
                return
            key = ""
            # initial Caesar thread
            thread = Frequency_Analysis.Thread(self, text, key, 0)
            # thread.final_result.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.start()
            self.pop_message_box("Decryption succeeded")
        except Exception as e:
            self.logging.log_error(e)

    def attack_multi(self):
        try:
            self.logging.log("Decrypt on your computer.")
            text = self.widgets_dict["Filepath"].get_text()
            if not os.path.exists(text):
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"FilePath\" box.")
                self.logging.log("\n")
                return
            if os.stat(str(text)).st_size > 2048 * 1024:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " In order to ensure the decryption speed, the file size should be within 2M.")
                self.logging.log("\n")
                return
            if text == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"FilePath\" box.")
                self.logging.log("\n")
                return
            key = ""
            # initial Caesar thread
            thread = Frequency_Analysis.Thread(self, text, key, 1)
            # thread.final_result.connect(self.widgets_dict["IntermediateValueTab"].append)
            thread.logging_result.connect(self.logging.log_decrypt_multi)
            thread.start()
            self.pop_message_box("Decryption succeeded")
        except Exception as e:
            self.logging.log_error(e)

    def export_file(self):
        self.logging.log("File exported successfully.")

    def encrypt_clean_import(self):
        self.widgets_dict["Filepath"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = FAWidget()
    app.exec_()