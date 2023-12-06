import csv
import re
import hashlib
from Hash import SM3
from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert

class PSWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Password System")
        self.widgets_dict = {}
        self.groups_config = [
            KeyGroup(name="Hash Function",
                     key_edit=[],
                     buttons=[],
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                                         items=["SHA1", "SHA256", "SHA3-256", "MD5", "SM3"])]
                     ),
            Group(name="Registration",
                  plain_text_edits=[PlainTextEdit(id="Account_Registration", label="Account (String)", default_text=""),
                                    PlainTextEdit(id="Password_Registration", label="Password (String)", default_text="")
                                    ],
                  buttons=[
                      Button(id="Sign Up", name="Sign Up", clicked_function=self.sign_up),
                      Button(id="Clean", name="Clean", clicked_function=self.password_registration_clean)
                  ]),
            Group(name="Login",
                  plain_text_edits=[PlainTextEdit(id="Account_Login", label="Account (String)", default_text=""),
                                    PlainTextEdit(id="Password_Login", label="Password (String)", default_text="")
                                    ],
                  buttons=[
                      Button(id="Login", name="Login In", clicked_function=self.login_in),
                      Button(id="Clean", name="Clean", clicked_function=self.login_clean)
                  ]),
            Group(name="Password Hash",
                  plain_text_edits=[PlainTextEdit(id="Password_Hash", label="Password Hash(hex)", default_text="", read_only=True)],
                  buttons=[])
        ]
        layout = QVBoxLayout()
        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        for group_config in self.groups_config:
            group_label = QLabel(group_config.name)
            layout.addWidget(group_label)

            if isinstance(group_config, KeyGroup):
                for edit in group_config.key_edit:
                    edit_label = QLabel(edit.label)
                    layout.addWidget(edit_label)

                    edit_text = edit.text
                    edit_widget = TextEdit(edit_text)  # 使用QLineEdit或其他适当的小部件替换此处的QLabel
                    layout.addWidget(edit_widget)

                    self.widgets_dict[edit.id] = edit_widget  # 将小部件与edit对象关联起来

                for combo in group_config.combo_box:
                    combo_label = QLabel(combo.label)
                    layout.addWidget(combo_label)

                    combo_items = combo.items
                    combo_widget = QComboBox()
                    combo_widget.addItems(combo_items)
                    layout.addWidget(combo_widget)

                    self.widgets_dict[combo.id] = combo_widget  # 将小部件与combo对象关联起来
                    combo_widget.currentIndexChanged.connect(combo.changed_function)  # 添加这一行以关联信号和槽函数

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
        self.logging.log("Password System algorithm has been imported.\n")
        self.path = Path.MENU_DIRECTORY
        self.hash_table_path = Path.MENU_DIRECTORY + "table/"
        self.hash_value = {"SHA1": "0D 5F 29 BC 67 14 8C 3E 2A 6B E4 D3 94 76 A7 A2 C4 EB 5B 03",
                           "SHA256": "F8 BA 9C 14 DB 55 C0 02 AD 91 69 37 82 D5 E7 65 8B 8E 65 EB 66 FE A2 85 1C 24 99 5C A2 F7 16 9A",
                           "SHA3-256": "12 C0 84 B6 76 7F 9A 78 1F 2C DF DE 23 F6 42 87 64 19 40 77 0B 95 01 42 18 28 4C 26 5C 6A 20 94",
                           "MD5": "7D 02 70 0A 9A F2 E8 D8 E3 0C F0 64 AB D8 1A C0",
                           "SM3": "BA 3F A9 D8 FB C3 27 7A 58 04 B1 2C AE F4 2B 87 BE F7 3A E8 BD 4C AF 20 1A E8 1C A7 7B F5 82 DF"}
        self.account_str = ["shuyuan1412SHA1", "shuyuan1412SHA256", "shuyuan1412SHA3-256", "shuyuan1412MD5", "shuyuan1412SM3"]
        self.account = None
        self.password = None
        self.information = None
        self.hash_mode = None

    def sign_up(self):
        self.account = self.widgets_dict["Account_Registration"].get_text()
        self.password = self.widgets_dict["Password_Registration"].get_text()
        if not self.error_password():
            return
        if self.account == "":
            self.logging.log("The Account cannot be empty.\n")
            self.pop_message_box("The Account cannot be empty.")
            return
        self.information = []
        self.information.append(self.account)
        self.hash_mode = self.widgets_dict["ComboBox"].get_text()
        if self.hash_mode == "SHA1":
            value = hashlib.sha1()
            value.update(self.password.encode())
            self.set_print_hash(value.hexdigest().upper())
        elif self.hash_mode == "SHA256":
            value = hashlib.sha256()
            value.update(self.password.encode())
            self.set_print_hash(value.hexdigest().upper())
        elif self.hash_mode == "SHA3-256":
            value = hashlib.sha3_256()
            value.update(self.password.encode())
            self.set_print_hash(value.hexdigest().upper())
        elif self.hash_mode == "MD5":
            value = hashlib.md5()
            value.update(self.password.encode())
            self.set_print_hash(value.hexdigest().upper())
        elif self.hash_mode == "SM3":
            password_list = list(self.password)
            password_list_sm3 = [0] * 6
            for j in range(6):
                password_list_sm3[j] = ord(password_list[j])
            thread = SM3.Thread(self, password_list_sm3)
            thread.final_result.connect(self.set_print_hash)
            thread.start()

    def error_password(self):
        if not self.password:
            self.logging.log("The Password cannot be empty.\n")
            self.pop_message_box("The Password cannot be empty.")
            return False
        if not self.password.isdigit():
            self.logging.log("The password should contain only numeric strings.\n")
            self.pop_message_box("The password should contain only numeric strings.")
            return False
        password_list = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", self.password).split(" ")
        if len(self.password) != 6:
            self.logging.log("The number of passwords is incorrect.\n")
            self.pop_message_box("The number of passwords is incorrect.")
            return False
        elif (int(password_list[0]) < 0) | (int(password_list[0]) > 99):
            self.logging.log("The first two digits of the password are incorrect.\n")
            self.pop_message_box("The first two digits of the password are incorrect.")
            return False
        elif (int(password_list[1]) < 1) | (int(password_list[1]) > 12):
            self.logging.log("The middle two digits of the password are incorrect.\n")
            self.pop_message_box("The middle two digits of the password are incorrect.")
            return False
        day_31 = {1, 3, 5, 7, 8, 10, 12}  # 大月
        day_30 = {4, 6, 9, 11}  # 小月
        if int(password_list[1]) in day_31:
            if (int(password_list[2]) < 1) | (int(password_list[2]) > 31):
                self.logging.log("The last two digits of the password are incorrect.\n")
                self.pop_message_box("The last two digits of the password are incorrect.")
                return False
        elif int(password_list[1]) in day_30:
            if (int(password_list[2]) < 1) | (int(password_list[2]) > 30):
                self.logging.log("The last two digits of the password are incorrect.\n")
                self.pop_message_box("The last two digits of the password are incorrect.")
                return False
        elif int(password_list[1]) == 2:
            if (((int(password_list[0]) % 4 == 0) & (int(password_list[0]) % 100 != 0)) | (int(password_list[0]) % 400 == 0)) & ((int(password_list[2]) < 1) | (int(password_list[2]) > 29)):
                self.logging.log("The last two digits of the password are incorrect.\n")
                self.pop_message_box("The last two digits of the password are incorrect.")
                return False
            elif (int(password_list[2]) < 1) | (int(password_list[2]) > 28):
                self.logging.log("The last two digits of the password are incorrect.\n")
                self.pop_message_box("The last two digits of the password are incorrect.")
                return False
        return True

    def set_print_hash(self, text):
        result = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", text)
        self.widgets_dict["Password_Hash"].set_text(result)
        self.information.append(result)
        self.information.append(self.hash_mode)
        with open(self.path + "Account Information.csv", 'r') as f:
            for row in csv.reader(f):
                if row[0] == self.account and row[2] == self.hash_mode:
                    self.logging.log("Account already exists. Please reset!\n")
                    self.pop_message_box("Account already exists. Please reset!")
                    f.close()
                    return
        with open(self.path + "Account Information.csv", 'a+', newline='') as f:
            csv.writer(f).writerow(self.information)
            f.close()
        self.widgets_dict["Account_Login"].set_text(self.account)
        self.widgets_dict["Password_Login"].set_text(self.password)
        self.pop_message_box("Registration is successful")

    def password_registration_clean(self):
        self.widgets_dict["Password_Registration"].set_text("")

    def login_in(self):
        account = self.widgets_dict["Account_Login"].get_text()
        password = self.widgets_dict["Password_Login"].get_text()
        hash_mode = self.widgets_dict["ComboBox"].get_text()
        flag = 1
        if account == "":
            self.logging.log("The account cannot be empty.\n")
            self.pop_message_box("The account cannot be empty.")
            return
        if password == "":
            self.logging.log("The password cannot be empty.\n")
            self.pop_message_box("The password cannot be empty.")
            return
        if account in self.account_str:
            if hash_mode in account:
                flag = self.hash_value[hash_mode]
            else:
                flag = 0
        else:
            with open(self.path + "Account Information.csv", 'r') as f_information:
                for i in csv.reader(f_information):
                    if i[0] == account:
                        if i[2] == hash_mode:
                            flag = i[1]
                        else:
                            flag = 0
                    elif flag != 0:
                        flag = 2
                f_information.close()
        if flag != 0 and flag != 2:
            with open(self.hash_table_path + hash_mode + ".csv", 'r') as f_hash:
                for j in csv.reader(f_hash):
                    if j[0] == password and j[1] == flag.replace(" ", ""):
                        self.widgets_dict["Password_Hash"].set_text(re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", j[1]))
                        flag = 1
                f_hash.close()
        if flag == 1:
            self.pop_message_box("Login successful.")
        elif flag == 0:
            self.pop_message_box("The hash algorithm was selected incorrectly.")
        elif flag == 2:
            self.pop_message_box("The account doesn't exist")
        else:
            self.logging.log("The password is incorrect.\n")
            self.pop_message_box("The password is incorrect.")

    def login_clean(self):
        self.widgets_dict["Account_Login"].set_text("")
        self.widgets_dict["Password_Login"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = PSWidget()
    app.exec_()