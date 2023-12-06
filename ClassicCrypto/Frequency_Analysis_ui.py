import os
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget

from ClassicCrypto import Frequency_Analysis
from Util.Modules import Button, PlainTextEdit, Group, ErrorType, TextEdit
from Util.Modules import CryptographyWidget
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
        layout = QVBoxLayout()
        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        for group_config in self.groups_config:
            group_label = QLabel(group_config.name)
            layout.addWidget(group_label)

            if isinstance(group_config, Group):
                for plain_text_edit in group_config.plain_text_edits:
                    self.widgets_dict[plain_text_edit.id] = plain_text_edit
                    edit_label = QLabel(plain_text_edit.label)
                    layout.addWidget(edit_label)

                    edit_text = plain_text_edit.text
                    edit_widget = TextEdit(edit_text)
                    layout.addWidget(edit_widget)
                    self.widgets_dict[plain_text_edit.id] = edit_widget  # 将QTextEdit小部件与plain_text_edit对象关联起来

            for button in group_config.buttons:
                self.widgets_dict[button.id] = button
                button_widget = QPushButton(button.name)
                button_widget.clicked.connect(button.clicked_function)
                layout.addWidget(button_widget)

        layout.addWidget(self.logging.log_widget)

        self.setWindowTitle("Cryptography Widget")
        self.setGeometry(300, 300, 500, 400)
        self.show()
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