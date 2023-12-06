from PyQt5 import QtCore


class EulerFunctionThread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)
    result = None

    def __init__(self, parent, m: int):
        super(EulerFunctionThread, self).__init__(parent)
        self.m = m

    @staticmethod
    def euler_phi(num: int) -> int:
        res = num
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                res = (res // i) * (i - 1)
            while num % i == 0:
                num //= i
        if num > 1:
            res = (res // num) * (num - 1)
        return res

    def euler_phi_run(self):
        self.result = str(self.euler_phi(self.m))
        self.print_result(self.result)

    def print_result(self, text: str):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.euler_phi_run()


class EulerTheoremThread(QtCore.QThread):
    print_final_result = QtCore.pyqtSignal(str)
    result = None

    def __init__(self, parent, a: int, n: int, m: int, phi_m: int, flag: int = 1):
        super(EulerTheoremThread, self).__init__(parent)
        self.a = a
        self.n = n
        self.m = m
        self.phi_m = phi_m
        self.flag = flag

    @staticmethod
    def power_mod(a: int, n: int, m: int) -> int:
        return a ** n % m

    def power_mod_run(self):
        if self.flag == 1:
            self.result = self.power_mod(self.a, self.n % self.phi_m, self.m)
        else:
            self.result = self.power_mod(self.a, self.n, self.m)
        self.result = str(self.result)
        self.print_result(self.result)

    def print_result(self, text: str):
        self.print_final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.power_mod_run()
