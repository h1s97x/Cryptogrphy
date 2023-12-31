import numpy
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QUrl

from ClassicCrypto.Hill import Hill
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import Path
class HillWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        # Hide the menu bar
        self.menuBar().setHidden(True)
        self.setWindowTitle("Hill")
        # set groups configurations
        # set plain text edit component configurations
        # set button component configurations;
        # id: the identity of the component
        # clicked_function: execute the function after the button clicked
        self.path = self.directory + "/ClassicCrypto/Hill/html/index.html"
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[PlainTextEdit(id="Key", label="Key (Str)",
                                   default_text="8 6 9 5\n6 9 5 10\n5 8 4 9\n10 6 11 4")],
                  buttons=[
                      Button(id="GenerateKey", name="GenerateKey", clicked_function=self.generate_key),
                      Button(id="ImportFile", name="Import File", clicked_function=self.import_key),
                  ]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plnaitext (Str)",
                                                  default_text="hill"),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean),
                      Button(id="ImportPlaintext", name="Import File", clicked_function=self.import_plaintext),
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Str)", default_text=""),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean),
                      Button(id="ExportFile", name="ExportFile", clicked_function=self.export_file),
                  ])
        ]
        # 在QWebEngineView中加载网址
        # 目前有一个故障，测试时在本目录下运行会导致运行目录设置为本目录，因此path路径就会不正确，但是在主窗口运行就正常
        self.webview.load(QUrl.fromLocalFile(self.path))
        self.render()
        self.logging.log("Hill algorithm has been imported.\n")

    def import_plaintext(self):
        try:

            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", self.directory)

            with open(file_path, "r") as file:
                file_content = file.read()
            self.widgets_dict["Plaintext"].set_text(file_content)
            self.widgets_dict["Plaintext_text"].set_text(file_path)

        except Exception as e:
            self.logging_error(e)
        self.logging.log("Plaintext file imported successfully.\n")

    def import_ciphertext(self):
        try:
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", self.directory)
            self.widgets_dict["Ciphertext_text"].set_text(file_path)
        except Exception as e:
            self.logging_error(e)
        self.logging.log("Ciphertext file imported successfully.\n")


    def import_key(self):
        try:
            file_path = Path.get_open_file_path_from_dialog(self, "Txt File (*.txt)", self.directory)

            with open(file_path, "r") as file:
                file_content = file.read()
            self.widgets_dict["Key"].set_text(file_content)

        except Exception as e:
            self.logging_error(e)
        self.logging.log("Plaintext file imported successfully.\n")
    def export_file(self):
        try:
            directory = Path.MENU_DIRECTORY

            with open( directory +'hill.txt', 'w') as f:
                f.write("解密后的内容：\n" + self.widgets_dict["_Plaintext"].get_text())


        except Exception as e:
            self.logging_error(e)
        self.logging.log("Plaintext file imported successfully.\n")


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
            # print the login information to main logging widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()

            # 这里由于QTextEdit类自带的方法不会保留\n这类特殊字符，导致key_error方法报错，原来的是用他自己写的get_text()方法获取，考虑复现
            key = self.widgets_dict["Key"].get_text()
            self.logging.log(key)
            if self.key_error(key) == 0:
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
            self.logging.log("Key:        " + "\n" + key)
            # initial Vigenere thread
            thread = Hill.Thread(self, plaintext, key, 0)
            thread.final_result.connect(self.func_encrypt)
            # start Vigenere thread
            thread.start()
        except Exception as e:
            self.logging_error(e)

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            key = self.widgets_dict["Key"].get_text()
            if self.key_error(key) == 0:
                return
            key_line = key.split('\n')
            if '' in key_line:
                key_line.remove('')
            row_key = len(key_line)  # 不能连着上两句写
            ciphertext = self.widgets_dict["Ciphertext"].get_text()
            self.logging.log(ciphertext)
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
            # 当密文字母的个数不是密钥矩阵行数的整数倍时，不能用于解密
            str_list_initial = list(ciphertext)
            str_list = []
            for i in range(0, len(ciphertext)):
                if not str_list_initial[i].isalpha():
                    continue
                else:
                    str_list.append(str_list_initial[i])
            if len(str_list) % row_key != 0:
                self.pop_message_box(ErrorType.LengthError.value + " You should check the \"Ciphertext\" input box.")
                self.logging.log("\n")
                return

            self.logging.log("Ciphertext: " + ciphertext)
            key = self.widgets_dict["Key"].get_text()
            self.logging.log("Key:        " + "\n" + key)
            thread = Hill.Thread(self, ciphertext, key, 1)
            thread.final_result.connect(self.func_decrypt)
            thread.start()
        except Exception as e:
            self.logging_error(e)

    def key_error(self, key):
        # 输入的密钥必须全为正整数
        key_str = key.replace("\n", " ").replace(" ", "")
        if not key_str.isdigit():
            self.pop_message_box(
                ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box." + "The key must be a matrix of positive integers.")
            self.logging.log("\n")
            return 0
        # 输入的密钥必须是矩阵的形式
        key_line = key.split('\n')
        if '' in key_line:
            key_line.remove('')
        key_row = len(key_line)
        if key_row != len(key_line):
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
            return 0
        key_column = key_row
        for i in range(key_row):
            key_column = len(key_line[i].split())
            if key_column == key_row:
                continue
            else:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
                self.logging.log("\n")
                return 0
        key_int = map(int, list(key.split()))
        key_list = []
        for i in key_int:
            key_list.append(i)
        key_matrix = numpy.array(key_list).reshape(key_row, key_column)
        if numpy.linalg.det(key_matrix) == 0:  # 判断密钥矩阵是否为可逆矩阵
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Key\" input box.")
            self.logging.log("\n")
            return 0

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def generate_key(self):
        pass

if __name__ == '__main__':
    app = QApplication([])
    window = HillWidget()
    app.exec_()