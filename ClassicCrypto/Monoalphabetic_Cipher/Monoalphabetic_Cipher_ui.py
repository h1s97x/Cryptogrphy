import os
from PyQt5.QtWidgets import QApplication

from ClassicCrypto.Monoalphabetic_Cipher import Monoalphabetic_Cipher
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import Path


class MonoalphabeticWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Monoalphabetic Cipher")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[PlainTextEdit(id="Key", label="Key (Str)",
                                   default_text="xyzz")],
                  buttons=[]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Str)",
                                                  default_text="Cryptor"),
                                    PlainTextEdit(id="Plaintext_text", label="File Path (Str)",
                                                  default_text="", read_only=True),
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
                                    PlainTextEdit(id="Ciphertext_text", label="File Path (Str)", default_text="",
                                                  read_only=True),
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
        self.render()
        self.logging.log("Monoalphabetic Cipher with Key has been imported.\n")

    def func_encrypt(self, str_data):
        self.logging.log("Ciphertext: " + str_data)
        self.widgets_dict["_Ciphertext"].set_text(str_data)
        self.logging.log("\n")

    def func_encrypt_text(self, str_data):
        self.logging.log("The storage path of the plaintext file is : " + str_data)
        self.widgets_dict["Ciphertext_text"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt(self, str_data):
        self.logging.log("Plaintext:  " + str_data)
        self.widgets_dict["_Plaintext"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt_text(self, str_data):
        self.logging.log("The storage path of the ciphertext file is : " + str_data)
        self.logging.log("\n")

    def import_plaintext(self):
        try:
            directory = Path.MENU_DIRECTORY
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", directory)
            self.widgets_dict["Plaintext_text"].set_text(file_path)
        except Exception as e:
            self.logging.log_error(e)
        self.logging.log("Plaintext file imported successfully.\n")

    def import_ciphertext(self):
        try:
            directory = Path.MENU_DIRECTORY
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", directory)
            self.widgets_dict["Ciphertext_text"].set_text(file_path)
        except Exception as e:
            self.logging.log_error(e)
        self.logging.log("Ciphertext file imported successfully.\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()
            key = self.widgets_dict["Key"].get_text()
            key = key.replace(' ', '')
            # 密钥不能为空
            if key == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # 密钥必须为字母
            for i in range(0, len(key)):
                if (key[i].isalpha()) == 0:
                    self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return
            # 密钥中不能含有汉字
            for ch in key:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return

            plaintext = self.widgets_dict["Plaintext"].get_text()
            plaintext = plaintext.replace(' ', '')
            # 明文不能为空
            if plaintext == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext\" input box.")
                self.logging.log("\n")
                return
            # 明文必须为字母
            for i in range(0, len(plaintext)):
                if (plaintext[i].isalpha()) == 0:
                    self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext\" input box.")
                    self.logging.log("\n")
                    return
            # 明文中不能含有汉字
            for ch in plaintext:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Plaintext\" input box.")
                    self.logging.log("\n")
                    return
            self.logging.log("Plaintext:  " + plaintext)
            self.logging.log("Key:        " + key)
            # initial Mono alphabetic Cipher thread
            thread = Monoalphabetic_Cipher.Thread(self, plaintext, key, 0)
            thread.final_result.connect(self.func_encrypt)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            key = self.widgets_dict["Key"].get_text()
            key = key.replace(' ', '')
            # 密钥不能为空
            if key == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # 密钥必须为字母
            for i in range(0, len(key)):
                if (key[i].isalpha()) == 0:
                    self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return
            # 密钥中不能含有汉字
            for ch in key:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return

            ciphertext = self.widgets_dict["Ciphertext"].get_text()
            ciphertext = ciphertext.replace(' ', '')
            # 密文不能为空
            if ciphertext == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return
            # 密文必须为字母
            for i in range(0, len(ciphertext)):
                if (ciphertext[i].isalpha()) == 0:
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
            thread = Monoalphabetic_Cipher.Thread(self, ciphertext, key, 1)
            thread.final_result.connect(self.func_decrypt)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    def computer_encrypt_text(self):
        try:
            self.logging.log("Encrypt on your computer.")
            key = self.widgets_dict["Key"].get_text()
            key = key.replace(' ', '')
            # 密钥不能为空
            if key == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # 密钥必须为字母
            for i in range(0, len(key)):
                if (key[i].isalpha()) == 0:
                    self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return
            # 密钥中不能含有汉字
            for ch in key:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return

            text = self.widgets_dict["Plaintext_text"].get_text()  # 明文路径
            # text = text.replace(' ','')
            if not os.path.exists(text):
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            if text == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            # initial Mono alphabetic cipher thread
            thread = Monoalphabetic_Cipher.Thread(self, text, key, 2)
            thread.final_result.connect(self.func_encrypt_text)
            thread.start()
            self.pop_message_box("Encryption succeeded.")
        except Exception as e:
            self.logging.log_error(e)

    def computer_decrypt_text(self):
        try:
            self.logging.log("Decrypt on your computer.")
            key = self.widgets_dict["Key"].get_text()
            key = key.replace(' ', '')
            # 密钥不能为空
            if key == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return
            # 密钥必须为字母
            for i in range(0, len(key)):
                if (key[i].isalpha()) == 0:
                    self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return
            # 密钥中不能含有汉字
            for ch in key:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return

            text = self.widgets_dict["Ciphertext_text"].get_text()
            if not os.path.exists(text):
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            if text == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext_text\" box.")
                self.logging.log("\n")
                return
            # initial Mono alphabetic cipher thread
            thread = Monoalphabetic_Cipher.Thread(self, text, key, 3)
            thread.final_result.connect(self.func_decrypt_text)
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
    window = MonoalphabeticWidget()
    app.exec_()