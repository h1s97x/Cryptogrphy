from PyQt5 import QtCore


class Thread(QtCore.QThread):
    print_final_result = QtCore.pyqtSignal(str)
    result = None

    def __init__(self, parent, a: list, m: list):
        super(Thread, self).__init__(parent)
        self.a = a
        self.m = m

    @staticmethod
    def crt(a: list, m: list) -> int:  # a和m要同大小
        M = 1
        for i in range(len(m)):
            M *= m[i]
        Mi = []
        for i in range(len(m)):
            Mi.append(M // m[i])
        Mi_inf = []
        for i in range(len(m)):
            Mi_inf.append(Thread.mod_inf(Mi[i], m[i]))
        result = 0
        for i in range(len(m)):
            result += (Mi[i] * Mi_inf[i] * a[i])
        return result % M

    @staticmethod
    def expand_gcd(a: int, b: int) -> tuple:
        if b == 0:
            return 1, 0, a
        else:
            x, y, q = Thread.expand_gcd(b, a % b)
            x, y = y, (x - (a // b) * y)
            return x, y, q

    @staticmethod
    def mod_inf(a: int, m: int) -> int:
        x, _, _ = Thread.expand_gcd(a, m)
        return (x + m) % m  # 防止负数

    def print_result(self, text: str):
        self.print_final_result.emit(text)

    def crt_run(self):
        self.result = str(self.crt(self.a, self.m))
        self.print_result(str(self.result))

    # execute this function after start function executed
    def run(self):
        self.crt_run()
