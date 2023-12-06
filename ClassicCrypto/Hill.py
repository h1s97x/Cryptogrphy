import numpy
from PyQt5 import QtCore


def multi_inverse(x, m):
    # 输入：求一个数x在模m下的乘法逆元
    # y的取值范围为[0,m)
    y = 0
    while y < m:
        res = (x * y) % m
        res = round(res)
        if res == 1:  # 模%d下,加***行列式值为%d，它的乘法逆元为%d" % (m, x, y)
            break
        else:
            y += 1
            if y == m:  # 不存在逆元
                return 0
    return y


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
        # 计算输入密钥的列数
        i = 0
        while i < len(self.key):
            if self.key[i] == '\n':
                break
            i += 1
        tmp_str = self.key[0:i]
        column_key = len(tmp_str.split())

        # 将密钥转换成整数型的矩阵
        key = self.key.split()
        key_int = map(int, list(key))
        key_list = []
        for i in key_int:
            key_list.append(i)
        row_key = len(key_list) // column_key
        key_arr = numpy.array(key_list).reshape(row_key, column_key)

        # 过滤掉明文中无效的字符
        str_list_initial = list(self.input_text)
        str_list = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():  # 判断是否为英文字母
                continue
            else:
                str_list.append(str_list_initial[i])

        # 将明文变为数字，并进行填充
        remain = len(str_list) % row_key  # 密钥矩阵的行数即为明文分组的长度
        if remain != 0:
            for i in range(0, row_key - remain):
                str_list.append('a')
        for i in range(len(str_list)):
            a = "a"
            if str_list[i].isupper():
                a = "A"
            str_list[i] = (ord(str_list[i]) - ord(a)) % 26  # 字母转数字

        # 将明文进行分组加密
        i = 0
        temp_number = []
        while i < len(str_list):
            str_arr = str_list[i:i + row_key]
            str_arr = numpy.array(str_arr)
            temp_list = (numpy.dot(str_arr, key_arr) % 26).tolist()
            temp_number = temp_number + temp_list
            i += row_key

        # 按照明文的格式输出密文,并区分大小写
        j = 0
        temp = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                temp.append(str_list_initial[i])
            else:
                a = 'a'
                if str_list_initial[i].isupper():
                    a = "A"
                temp.append(chr(temp_number[j] + ord(a)))
                j += 1
        if j != len(temp_number):
            for i in range(j, len(temp_number)):
                temp.append(chr(temp_number[i] + ord('a')))
        result = "".join(temp)
        return result

    def decrypt(self):
        # 计算输入密钥的列数
        i = 0
        while i < len(self.key):
            if self.key[i] == '\n':
                break
            i += 1
        tmp_str = self.key[0:i]
        column_key = len(tmp_str.split())

        # 将密钥转换成整数型的矩阵
        key = self.key.split()
        key_int = map(int, list(key))
        key_list = []
        for i in key_int:
            key_list.append(i)
        row_key = len(key_list) // column_key
        key_arr = numpy.array(key_list).reshape(row_key, column_key)
        key_arr_det = numpy.linalg.det(key_arr)  # 行列式
        key_arr_inverse = numpy.linalg.inv(key_arr)  # 逆矩阵
        key_arr_adjoint = key_arr_inverse * key_arr_det % 26  # 伴随矩阵
        key_arr_adjoint = numpy.around(key_arr_adjoint)
        key_arr_adjoint = key_arr_adjoint.astype(int)
        y = multi_inverse(key_arr_det, 26)
        key_arr_inverse = y * key_arr_adjoint % 26

        # # 求密钥矩阵的逆矩阵
        # key_arr_inverse = numpy.linalg.inv(key_arr) % 26
        #
        # key_arr_inverse = numpy.around(key_arr_inverse)
        #
        # # 求逆之后变成浮点型存在误差，进行四舍五入
        # # key_arr_inverse += 0.5
        # key_arr_inverse = key_arr_inverse.astype(numpy.int)

        # 过滤掉密文中无效的字符
        str_list_initial = list(self.input_text)
        str_list = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                continue
            else:
                str_list.append(str_list_initial[i])

        # 将密文变为数字
        for i in range(len(str_list)):
            a = "a"
            if str_list[i].isupper():
                a = "A"
            str_list[i] = (ord(str_list[i]) - ord(a)) % 26

        # 将密文进行分组解密
        i = 0
        temp_number = []
        while i < len(str_list):
            str_arr = str_list[i:i + row_key]
            str_arr = numpy.array(str_arr)
            temp_list = (numpy.dot(str_arr, key_arr_inverse) % 26).tolist()
            temp_number = temp_number + temp_list
            i += row_key

        # 按照密文的格式输出明文,并区分大小写
        j = 0
        temp = []
        for i in range(0, len(self.input_text)):
            if not str_list_initial[i].isalpha():
                temp.append(str_list_initial[i])
            else:
                a = 'a'
                if str_list_initial[i].isupper():
                    a = "A"
                temp.append(chr(temp_number[j] + ord(a)))
                j += 1
        result = "".join(temp)
        return result
