from PyQt5 import QtCore


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, key, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key = key
        self.encrypt_selected = encrypt_selected

    # encrypt script
    def encrypt_run(self):
        result = self.encrypt()
        self.print_final_result(result)

    # decrypt script
    def decrypt_run(self):
        result = self.decrypt()
        self.print_final_result(result)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        else:
            self.decrypt_run()

    def encrypt(self):
        # 过滤掉明文中无效的字符
        str_list_initial = list(self.input_text)
        str_list = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                continue
            else:
                str_list.append(str_list_initial[i])

        # 过滤掉密钥中无效的字符
        key_list_initial = list(self.key.upper())
        key_list = []
        for i in range(0, len(self.key)):
            if not key_list_initial[i].isalpha():
                continue
            else:
                key_list.append(key_list_initial[i])

        # 维吉尼亚加密算法
        len_key = len(key_list)
        cycles = len(str_list) // len_key  # 循环次数
        remain = len(str_list) % len_key  # 余数
        for i in range(0, cycles):
            for j in range(0, len_key):
                a = "a"
                if str_list[i * len_key + j].isupper():
                    a = "A"
                str_list[i * len_key + j] = chr(
                    (ord(str_list[i * len_key + j]) - ord(a) + ord(key_list[j]) - ord('A')) % 26 + ord(a))
        for i in range(0, remain):
            a = "a"
            if str_list[cycles * len_key + i].isupper():
                a = "A"
            str_list[cycles * len_key + i] = chr(
                (ord(str_list[cycles * len_key + i]) - ord(a) + ord(key_list[i]) - ord('A')) % 26 + ord(a))

        # 按照明文的格式输出密文
        temp = []
        j = 0
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                temp.append(str_list_initial[i])
            else:
                temp.append(str_list[j])
                j += 1
        result = "".join(temp)
        return result

    def decrypt(self):
        # 过滤掉密文中无效的字符
        str_list_initial = list(self.input_text)
        str_list = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                continue
            else:
                str_list.append(str_list_initial[i])

        # 过滤掉密钥中无效的字符
        key_list_initial = list(self.key.upper())
        key_list = []
        for i in range(0, len(self.key)):
            if not key_list_initial[i].isalpha():
                continue
            else:
                key_list.append(key_list_initial[i])

        # 维吉尼亚解密算法
        len_key = len(key_list)
        cycles = len(str_list) // len_key  # 循环次数
        remain = len(str_list) % len_key  # 余数
        for i in range(0, cycles):
            for j in range(0, len_key):
                a = "a"
                if str_list[i * len_key + j].isupper():
                    a = "A"
                str_list[i * len_key + j] = chr(
                    (ord(str_list[i * len_key + j]) - ord(a) - (ord(key_list[j]) - ord('A'))) % 26 + ord(a))
        for i in range(0, remain):
            a = "a"
            if str_list[cycles * len_key + i].isupper():
                a = "A"
            str_list[cycles * len_key + i] = chr(
                (ord(str_list[cycles * len_key + i]) - ord(a) - (ord(key_list[i]) - ord('A'))) % 26 + ord(a))

        # 按照密文的格式输出明文
        temp = []
        j = 0
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                temp.append(str_list_initial[i])
            else:
                temp.append(str_list[j])
                j += 1
        result = "".join(temp)
        return result
