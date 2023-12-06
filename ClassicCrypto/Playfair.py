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

    # 获取字符在密码表中的位置，i为行，j为列
    @staticmethod
    def get_matrix_index(ch, letter_matrix):
        for i in range(len(letter_matrix)):
            for j in range(len(letter_matrix)):
                if letter_matrix[i][j] == ch:
                    return i, j

    def encrypt(self):
        # 过滤掉密钥中无效的字符
        key_list_initial = list(self.key.upper())
        key_list = []
        j = 0
        for i in range(len(self.key)):
            if not key_list_initial[i].isalpha():
                continue
            else:
                key_list.append(key_list_initial[i])

        # 去除密钥中重复的字母
        key = ''
        for ch in key_list:
            if ch == 'J':
                ch = 'I'
            if ch in key:
                continue
            else:
                key += ch

        # 根据密钥建立5*5的密钥字母矩阵
        letter_matrix = ['', '', '', '', '']
        letter_list = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        for ch in letter_list:
            if ch not in key:
                key += ch
        j = 0
        for i in range(len(key)):
            letter_matrix[j] += key[i]  # j用来定位字母表的行
            if (i + 1) % 5 == 0:
                j += 1

        # 明文分组后，若有重复字母，中间插入字母'Q'
        str_list_initial = list(self.input_text)
        str_list_new = []
        flag = 0
        i = 0
        k = 0
        while i < len(str_list_initial):
            str_list_new.append(str_list_initial[i])
            if str_list_initial[i].isalpha():  # 如果是明文是字母的话，
                j = i + 1  # 则开始对该字母之后的明文进行遍历，
                while j < len(str_list_initial):  # 直到遍历到字母，进行加密
                    if str_list_initial[j].isalpha():
                        if str_list_initial[i] == str_list_initial[j]:
                            str_list_new.append('Q')
                            flag = 1
                        else:
                            str_list_new.append(str_list_initial[j])
                        break  # 每组明文对检验完成后，结束本次对明文的遍历
                    else:
                        str_list_new.append(str_list_initial[j])
                        j += 1
                if flag == 1:
                    i = j
                    flag = 0
                else:
                    i = j + 1
                continue
            i += 1

        # 过滤掉明文中无效的字符，如果最后明文长度为奇数，在末尾添加字母'Z'
        str_list = []
        for i in range(len(str_list_new)):
            if not str_list_new[i].isalpha():
                continue
            else:
                str_list.append(str_list_new[i])
        if len(str_list) % 2 != 0:
            str_list.append('Z')
            str_list_new.append('Z')

        # Playfair加密算法
        i = 0
        while i < len(str_list) - 1:
            j = i + 1
            if str_list[i].upper() == 'J':
                x = self.get_matrix_index('I', letter_matrix)
            else:
                x = self.get_matrix_index(str_list[i].upper(), letter_matrix)
            if str_list[j].upper() == 'J':
                y = self.get_matrix_index('I', letter_matrix)
            else:
                y = self.get_matrix_index(str_list[j].upper(), letter_matrix)
            # 如果在同一行
            if x[0] == y[0]:
                str_list[i] = letter_matrix[x[0]][(x[1] + 1) % 5]
                str_list[j] = letter_matrix[y[0]][(y[1] + 1) % 5]
            # 如果在同一列
            elif x[1] == y[1]:
                str_list[i] = letter_matrix[(x[0] + 1) % 5][x[1]]
                str_list[j] = letter_matrix[(y[0] + 1) % 5][y[1]]
            # 如果不同行不同列
            else:
                str_list[i] = letter_matrix[x[0]][y[1]]
                str_list[j] = letter_matrix[y[0]][x[1]]
            i = j + 1

        # 按照明文的格式输出密文，非字母的字符直接输出，并且进行大小写转换
        temp = []
        j = 0
        for i in range(0, len(str_list_new)):
            if not str_list_new[i].isalpha():
                temp.append(str_list_new[i])
            else:
                if not str_list_new[i].isupper():
                    temp.append(str_list[j].lower())
                else:
                    temp.append(str_list[j])
                j += 1
        result = "".join(temp)
        return result

    def decrypt(self):
        # 过滤掉密钥中无效的字符
        key_list_initial = list(self.key.upper())
        key_list = []
        j = 0
        for i in range(len(self.key)):
            if not key_list_initial[i].isalpha():
                continue
            else:
                key_list.append(key_list_initial[i])

        # 去除密钥中重复的字母
        key = ''
        for ch in key_list:
            if ch == 'J':
                ch = 'I'
            if ch in key:
                continue
            else:
                key += ch

        # 根据密钥建立5*5的密钥字母矩阵
        letter_matrix = ['', '', '', '', '']
        letter_list = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        for ch in letter_list:
            if ch not in key:
                key += ch
        j = 0
        for i in range(len(key)):
            letter_matrix[j] += key[i]  # j用来定位字母表的行
            if (i + 1) % 5 == 0:
                j += 1

        # 过滤掉密文中无效的字符
        str_list_initial = list(self.input_text)
        str_list = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                continue
            else:
                str_list.append(str_list_initial[i])

        # Playfair解密算法
        i = 0
        plaintext = []
        while i < len(str_list) - 1:
            j = i + 1
            if str_list[i].upper() == 'J':
                x = self.get_matrix_index('I', letter_matrix)
            else:
                x = self.get_matrix_index(str_list[i].upper(), letter_matrix)
            if str_list[j].upper() == 'J':
                y = self.get_matrix_index('I', letter_matrix)
            else:
                y = self.get_matrix_index(str_list[j].upper(), letter_matrix)
            # 如果在同一行
            if x[0] == y[0]:
                plaintext.append(letter_matrix[x[0]][(x[1] - 1) % 5])
                plaintext.append(letter_matrix[y[0]][(y[1] - 1) % 5])
            # 如果在同一列
            elif x[1] == y[1]:
                plaintext.append(letter_matrix[(x[0] - 1) % 5][x[1]])
                plaintext.append(letter_matrix[(y[0] - 1) % 5][y[1]])
            # 如果不同行不同列
            else:
                plaintext.append(letter_matrix[x[0]][y[1]])
                plaintext.append(letter_matrix[y[0]][x[1]])
            i = j + 1

        # 按照密文的格式输出明文
        temp = []
        j = 0
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                temp.append(str_list_initial[i])
            else:
                if not str_list_initial[i].isupper():
                    temp.append(plaintext[j].lower())
                else:
                    temp.append(plaintext[j])
                j += 1
        result = "".join(temp)
        return result
