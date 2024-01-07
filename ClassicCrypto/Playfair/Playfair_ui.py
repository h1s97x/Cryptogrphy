from PyQt5.QtWidgets import QApplication

from ClassicCrypto.Playfair import Playfair
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget


class PlayfairWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Playfair")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[PlainTextEdit(id="Key", label="Key (Str)",
                                   default_text="PLAYFAIR IS DIGRAM CIPHER")],
                  buttons=[]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Str)",
                                                  default_text="playfair cipher"),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Str)", default_text=""),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]
        self.render()
        self.logging.log("Playfair algorithm has been imported.\n")

    def func_encrypt(self, str_data):
        self.logging.log("Ciphertext: " + str_data)
        self.widgets_dict["_Ciphertext"].set_text(str_data)
        self.widgets_dict["Ciphertext"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt(self, str_data):
        self.logging.log("Plaintext:  " + str_data)
        self.widgets_dict["_Plaintext"].set_text(str_data)
        self.logging.log("\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()
            # get text from target widget
            key = self.widgets_dict["Key"].get_text()
            # 密钥不能为空
            if key == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return

            # 密钥中不能含有汉字
            for ch in key:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return

            # 密钥中至少含有一个字母
            flag = 0
            for i in range(0, len(key)):
                if key[i].isalpha():
                    flag = 1
                    break
            if flag == 0:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return

            plaintext = self.widgets_dict["Plaintext"].get_text()
            # 明文不能为空
            if plaintext == '':
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
            # initial  thread
            thread = Playfair.Thread(self, plaintext, key, 0)
            thread.final_result.connect(self.func_encrypt)
            # start Vigenere thread
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            key = self.widgets_dict["Key"].get_text()
            # 密钥不能为空
            if key == '':
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return

            # 密钥中不能含有汉字
            for ch in key:
                if u'\u4e00' <= ch <= u'\u9fff':
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Key\" input box.")
                    self.logging.log("\n")
                    return

            # 密钥中至少含有一个字母
            flag = 0
            for i in range(0, len(key)):
                if key[i].isalpha():
                    flag = 1
                    break
            if flag == 0:
                self.logging.log(ErrorType.NotMeetRequirementError.value + "\n")
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

            # 如果密文中包含的字母数是奇数，则提示用户输入长度错误
            str_list_initial = list(ciphertext)
            str_list = []
            for i in range(0, len(ciphertext)):
                if not str_list_initial[i].isalpha():
                    continue
                else:
                    str_list.append(str_list_initial[i])
            if len(str_list) % 2 != 0:
                self.pop_message_box(ErrorType.LengthError.value + " You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return

            self.logging.log("Ciphertext: " + ciphertext)
            self.logging.log("Key:        " + key)
            thread = Playfair.Thread(self, ciphertext, key, 1)
            thread.final_result.connect(self.func_decrypt)
            thread.start()
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
    window = PlayfairWidget()
    app.exec_()