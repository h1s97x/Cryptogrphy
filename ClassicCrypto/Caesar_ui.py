import os
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget

from ClassicCrypto import Caesar
from Util.Modules import Button, PlainTextEdit, Group, ErrorType, TextEdit
from Util.Modules import CryptographyWidget
from Util import Path

class CaesarWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Caesar")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
            plain_text_edits = [PlainTextEdit(id="Key", label="Key (Int)",
                                              default_text="3")],
            buttons=[]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Str)",
                                                  default_text="China"),
                                    PlainTextEdit(id="Plaintext_text", label="File Path (Text)",
                                                  default_text=""),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="ImportFile", name="Import File", clicked_function=self.import_plaintext),
                      Button(id="ComputerEncrypt_text", name="Encrypt Text (PC)",
                             clicked_function=self.computer_encrypt_text),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Str)", default_text=""),
                                    PlainTextEdit(id="Ciphertext_text", label="File Path (Text)", default_text=""),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="ImportFile", name="Import File", clicked_function=self.import_ciphertext),
                      Button(id="ComputerDecrypt", name="Decrypt Text (PC)",
                             clicked_function=self.computer_decrypt_text),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
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


        self.setGeometry(300, 300, 500, 400)
        self.show()
        self.logging.log("Caesar algorithm has been imported.\n")

    def func_encrypt(self, str_data):
        self.logging.log("Ciphertext: " + str_data)
        self.widgets_dict["_Ciphertext"].set_text(str_data)
        self.widgets_dict["Ciphertext"].set_text(str_data)
        self.logging.log("\n")

    def func_encrypt_text(self, str_data):
        self.logging.log("Ciphertext: " + str_data)
        self.widgets_dict["Ciphertext_text"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt(self, str_data):
        self.logging.log("Plaintext:  " + str_data)
        self.widgets_dict["_Plaintext"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt_text(self, str_data):
        self.logging.log("Plaintext:  " + str_data)
        self.logging.log("\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()
            key = self.widgets_dict["Key"].get_text()
            # 密钥必须为数字
            if not key.isdigit():
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # 明文不能为空
            plaintext = self.widgets_dict["Plaintext"].get_text()
            if plaintext == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            # 明文中含有汉字
            for ch in plaintext:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Plaintext\" input box.")
                    self.logging.log("\n")
                    return
            self.logging.log("Plaintext:  " + plaintext)
            self.logging.log("Key:        " + key)
            # initial Caesar thread
            thread = Caesar.Thread(self, plaintext, key, 0)
            thread.final_result.connect(self.func_encrypt)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    def import_plaintext(self):
        try:
            directory = Path.MENU_DIRECTORY
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", directory)

            with open(file_path, "r") as file:
                file_content = file.read()
            self.widgets_dict["Plaintext"].set_text(file_content)
            self.widgets_dict["Plaintext_text"].set_text(file_path)

        except Exception as e:
            self.logging_error(e)
        self.logging.log("Plaintext file imported successfully.\n")

    def import_ciphertext(self):
        try:
            directory = Path.MENU_DIRECTORY
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", directory)
            self.widgets_dict["Ciphertext_text"].set_text(file_path)
        except Exception as e:
            self.logging_error(e)
        self.logging.log("Ciphertext file imported successfully.\n")

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            key = self.widgets_dict["Key"].get_text()
            # 密钥必须为数字
            if not key.isdigit():
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            ciphertext = self.widgets_dict["Ciphertext"].get_text()
            # 密文不能为空
            if ciphertext == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            # 密文中不能含有汉字
            for ch in ciphertext:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Ciphertext\" input box.")
                    self.logging.log("\n")
                    return
            self.logging.log("Ciphertext: " + ciphertext)
            self.logging.log("Key:        " + key)
            thread = Caesar.Thread(self, ciphertext, key, 1)
            thread.final_result.connect(self.func_decrypt)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    def computer_encrypt_text(self):
        try:
            self.logging.log("Encrypt on your computer.")
            text = self.widgets_dict["Plaintext_text"].get_text()
            if not os.path.exists(text):
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            if text == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            key = self.widgets_dict["Key"].get_text()
            # initial Caesar thread
            thread = Caesar.Thread(self, text, key, 2)
            thread.final_result.connect(self.func_encrypt_text)
            thread.start()
            self.pop_message_box("Encryption succeeded.")
        except Exception as e:
            self.logging.log_error(e)

    def computer_decrypt_text(self):
        try:
            self.logging.log("Decrypt on your computer.")
            text = self.widgets_dict["Ciphertext_text"].get_text()
            if not os.path.exists(text):
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            if text == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            key = self.widgets_dict["Key"].get_text()
            # initial Caesar thread
            thread = Caesar.Thread(self, text, key, 3)
            thread.final_result.connect(self.func_encrypt_text)
            thread.start()
            self.pop_message_box("Decryption succeeded.")
        except Exception as e:
            self.logging.log_error(e)

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")
if __name__ == '__main__':
    app = QApplication([])
    window = CaesarWidget()
    app.exec_()