import logging
from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    P = 0
    Q = 0
    numb = 0x7fc
    A = 0
    B = 0
    C = 0
    D = 0
    n1 = 0
    n2 = 0
    n3 = 0
    n4 = 0
    ones = 0
    zeros = 0
    all = 0
    n = [int(0)] * 4
    H = [int(0)] * 5

    def __init__(self, parent, input_text, key, encrypt_selected, key_size=160, block_size=128):
        """
        Initialize an instance of the Simon block cipher.
        param key: Int representation of the encryption key
        :param key_size: Int representing the encryption key in bits
        :param block_size: Int representing the block size in bits
        :return: None
        """
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key = key
        self.n = 7
        self.encrypt_selected = encrypt_selected
        self.key_size = key_size
        self.block_size = block_size

    # encrypt script
    def encrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Encryption begins******************************/")
        self.print_intermediate_value(
            "\nPlaintext:" + TypeConvert.int_to_str(self.input_text, int(self.block_size / 8)))
        self.print_intermediate_value("Key:" + TypeConvert.int_to_str(self.key, int(self.key_size / 8)))
        self.print_intermediate_value('Intermediate values')
        result = self.encrypt(self.input_text)
        self.print_intermediate_value("Encrypted:" + TypeConvert.int_to_str(result, int(self.block_size / 8)))
        self.print_intermediate_value("Encryption completed\n\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, int(self.block_size / 8)))

    # decrypt script
    def decrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Decryption begins******************************/")
        self.print_intermediate_value(
            "\nCiphertext:" + TypeConvert.int_to_str(self.input_text, int(self.block_size / 8)))
        self.print_intermediate_value("Key:" + TypeConvert.int_to_str(self.key, int(self.key_size / 8)))
        result = self.decrypt(self.input_text)
        self.print_intermediate_value("Decrypted:" + TypeConvert.int_to_str(result, int(self.block_size / 8)))
        self.print_intermediate_value("Decryption completed\n\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, int(self.block_size / 8)))

    def print_intermediate_value(self, string):
        self.intermediate_value.emit(string)

    def print_final_result(self, string):
        self.final_result.emit(string)

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        else:
            self.decrypt_run()

    def encrypt(self, plaintext):
        return self.coding(plaintext, self.key, self.n)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

    @staticmethod
    def K(t):
        if 0 <= t <= 19:
            return 0x5a827999
        if 20 <= t <= 39:
            return 0x6ed9eba1
        if 40 <= t <= 59:
            return 0x8f1bbcdc
        if 60 <= t <= 79:
            return 0xca62c1d6

    @staticmethod
    def f(t, B, C, D):
        if 0 <= t <= 19:
            return (B & C) | ((~B) & D)
        if 20 <= t <= 39 or 60 <= t <= 79:
            return B ^ C ^ D
        if 40 <= t <= 59:
            return (B & C) | (B & D) | (C & D)

    @staticmethod
    def overflow_add(num1, num2):
        return (num1 + num2) % 0x100000000

    @staticmethod
    def circular_shift_right(int_value, k):
        mask = 2 ** k - 1
        right_v = (int_value & mask)
        left_v = int_value & (0xffffffff - mask)
        int_value = (right_v << (32 - k)) | (left_v >> k)
        return int_value

    def G(self, a, i):
        W = [int(0)] * 80
        W[0] = i
        for t in range(1, 16):
            W[t] = 0
        for t in range(16, 80):
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]
        A = a[0]
        B = a[1]
        C = a[2]
        D = a[3]
        E = a[4]
        for t in range(0, 80):
            tmp = self.overflow_add(self.overflow_add(
                self.overflow_add(self.overflow_add(self.circular_shift_right(A, 27), self.f(t, B, C, D)), E), W[t]),
                self.K(t))
            E = D
            D = C
            C = self.circular_shift_right(B, 2)
            B = A
            A = tmp
        self.H[0] = self.overflow_add(a[0], A)
        self.H[1] = self.overflow_add(a[1], B)
        self.H[2] = self.overflow_add(a[2], C)
        self.H[3] = self.overflow_add(a[3], D)
        self.H[4] = self.overflow_add(a[4], E)

    def Gamma(self, a, i):
        self.G(a, int(i / 5))
        return self.H[i % 5]

    def T(self, exkey, index):
        return self.Gamma(exkey, index)

    def S(self, exkey, index):
        return self.Gamma(exkey, index + 0x1000)

    def R(self, exkey, index):
        return self.Gamma(exkey, index + 0x2000)

    def initialize_seal(self, n, l, exkey):
        self.A = n ^ self.R(exkey, 4 * l)
        self.B = self.circular_shift_right(n, 8) ^ self.R(exkey, 4 * l + 1)
        self.C = self.circular_shift_right(n, 16) ^ self.R(exkey, 4 * l + 2)
        self.D = self.circular_shift_right(n, 24) ^ self.R(exkey, 4 * l + 3)
        for j in range(1, 3):
            P = self.A & self.numb
            self.B = self.overflow_add(self.B, self.T(exkey, int(P / 4)))
            self.A = self.circular_shift_right(self.A, 9)
            P = self.B & self.numb
            self.C = self.overflow_add(self.C, self.T(exkey, int(P / 4)))
            self.B = self.circular_shift_right(self.B, 9)
            P = self.C & self.numb
            self.D = self.overflow_add(self.D, self.T(exkey, int(P / 4)))
            self.C = self.circular_shift_right(self.C, 9)
            P = self.D & self.numb
            self.A = self.overflow_add(self.A, self.T(exkey, int(P / 4)))
            self.D = self.circular_shift_right(self.D, 9)
        self.n1 = self.A
        self.n2 = self.B
        self.n3 = self.C
        self.n4 = self.D
        P = self.A & self.numb
        self.B = self.overflow_add(self.B, self.T(exkey, int(P / 4)))
        self.A = self.circular_shift_right(self.A, 9)
        P = self.B & self.numb
        self.C = self.overflow_add(self.C, self.T(exkey, int(P / 4)))
        self.B = self.circular_shift_right(self.B, 9)
        P = self.C & self.numb
        self.D = self.overflow_add(self.D, self.T(exkey, int(P / 4)))
        self.C = self.circular_shift_right(self.C, 9)
        P = self.D & self.numb
        self.A = self.overflow_add(self.A, self.T(exkey, int(P / 4)))
        self.D = self.circular_shift_right(self.D, 9)

    def seal(self, n, y, exkey):
        lenth = 4
        k = 0
        for i in range(0, lenth):
            y[i] = 0
        l = 0
        while 1:
            self.initialize_seal(n, l, exkey)
            l += 1
            for i in range(1, 65):
                P = self.A & self.numb
                self.B = self.overflow_add(self.B, self.T(exkey, int(P / 4)))
                self.A = self.circular_shift_right(self.A, 9)
                self.B = self.B ^ self.A

                Q = self.B & self.numb
                self.C ^= self.T(exkey, int(Q / 4))
                self.B = self.circular_shift_right(self.B, 9)
                self.C = self.overflow_add(self.C, self.B)

                P = self.overflow_add(P, self.C) & self.numb
                self.D = self.overflow_add(self.D, self.T(exkey, int(P / 4)))
                self.C = self.circular_shift_right(self.C, 9)
                self.D = self.D ^ self.C

                Q = self.overflow_add(Q, self.D) & self.numb
                self.A ^= self.T(exkey, int(Q / 4))
                self.D = self.circular_shift_right(self.D, 9)
                self.A = self.overflow_add(self.A, self.D)

                P = self.overflow_add(P, self.A) & self.numb
                self.B ^= self.T(exkey, int(P / 4))
                self.A = self.circular_shift_right(self.A, 9)

                Q = self.overflow_add(Q, self.B) & self.numb
                self.C = self.overflow_add(self.C, self.T(exkey, int(Q / 4)))
                self.B = self.circular_shift_right(self.B, 9)

                P = self.overflow_add(P, self.C) & self.numb
                self.D ^= self.T(exkey, int(P / 4))
                self.C = self.circular_shift_right(self.C, 9)

                Q = self.overflow_add(Q, self.D) & self.numb
                self.A = self.overflow_add(self.A, self.T(exkey, int(Q / 4)))
                self.D = self.circular_shift_right(self.D, 9)

                y[k] = self.overflow_add(self.B, self.S(exkey, 4 * i - 4))
                k += 1
                y[k] = self.C ^ self.S(exkey, 4 * i - 3)
                k += 1
                y[k] = self.overflow_add(self.D, self.S(exkey, 4 * i - 2))
                k += 1
                y[k] = self.A ^ self.S(exkey, 4 * i - 1)
                k += 1
                if k >= 4:
                    return
                if i % 2 == 0:
                    self.A = self.overflow_add(self.A, self.n1)
                    self.C = self.overflow_add(self.C, self.n2)
                else:
                    self.A = self.overflow_add(self.A, self.n3)
                    self.C = self.overflow_add(self.C, self.n4)

    def coding(self, text, key, n):
        y = [int(0)] * 4
        extext = [0] * 4
        exkey = [0] * 5
        output = 0
        for i in range(0, 4):
            extext[i] = (text >> (32 * (3 - i))) & 0xffffffff
        for i in range(0, 5):
            exkey[i] = (key >> (32 * (4 - i))) & 0xffffffff
        self.seal(n, y, exkey)
        for i in range(0, 4):
            extext[i] ^= y[i]
            output |= (extext[i] << (96 - 32 * i))
            if i == 3:
                return output


if __name__ == 'main':
    text = [0x30313233, 0x34353637, 0x38393031, 0x32333435]
    key = [0x30313233, 0x34353637, 0x38393031, 0x32333435, 0x36373839]
    enc = [int(0)] * 4
    L = 128
    n = 7
