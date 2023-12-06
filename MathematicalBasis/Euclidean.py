from PyQt5 import QtCore


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, a, b):
        super(Thread, self).__init__(parent)
        self.a = a
        self.b = b

    # gcd script
    def gcd_run(self):
        result = str(self.gcd(self.a, self.b))
        self.print_final_result(result)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.gcd_run()

    @staticmethod
    def gcd(a, b):
        while a != 0:
            a, b = b % a, a
        return b
