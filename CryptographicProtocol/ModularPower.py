from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    string = QtCore.pyqtSignal(str)
    is_finished = QtCore.pyqtSignal()

    def __init__(self, parent, base, index, modulus, length):
        super(Thread, self).__init__(parent)
        self.base = int(base)
        self.index = int(index)
        self.modulus = int(modulus)
        self.length = int(length)

    # 平方乘算法实现模乘：返回值为x ** exp % n
    @staticmethod
    def pow_mod_n(x, exp, n):
        t = 1
        x_exp = x
        while exp > 0:
            if exp & 1 != 0:
                t *= x_exp
                t %= n
            x_exp *= x_exp
            x_exp %= n
            exp >>= 1
        return t

    # generate script
    def generate_run(self):
        result = self.pow_mod_n(self.base, self.index, self.modulus)
        # 转成16进制的表示
        result = TypeConvert.int_to_str(result, self.length)
        self.print_str(result)

    def print_str(self, result):
        self.string.emit(result)

    # execute this function after start function executed
    def run(self):
        self.generate_run()
