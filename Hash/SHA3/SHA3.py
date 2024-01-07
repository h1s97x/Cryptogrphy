import logging
from copy import deepcopy
from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, message, d, l=6):
        super(Thread, self).__init__(parent)
        self.message = message
        self.d = d
        self.l = l
        self.w = 2 ** l
        self.b = 25 * self.w
        self.A = [[0] * 5 for _ in range(5)]

    # hash script
    def hash_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Hash begins")
        if self.message is None:
            self.print_intermediate_value("Message:\nNone")
        else:
            self.print_intermediate_value("Message:\n" + self.message)
        result = self.hash()
        self.print_intermediate_value("Hash:\n" + result)
        self.print_intermediate_value("Hash completed\n\n")
        self.print_final_result(result)

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.hash_run()

    def hash(self):
        c = self.d * 2
        r = self.b - c
        if self.message is None:
            self.message = ''
        result = self._sponge(r, self.message + '01', self.d)
        result = self._small_endian(result)
        return TypeConvert.int_to_str(int(result, 2), self.d // 8)

    def _theta(self):
        C = [0] * 5
        D = [0] * 5
        for x in range(5):
            C[x] = self.A[x][0] ^ self.A[x][1] ^ self.A[x][2] ^ self.A[x][3] ^ self.A[x][4]
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ C[(x + 1) % 5] >> 1 ^ C[(x + 1) % 5] << (self.w - 1) & (2 ** self.w - 1)
        for x in range(5):
            for y in range(5):
                self.A[x][y] ^= D[x]

    def _rho(self):
        x, y = 1, 0
        for t in range(24):
            self.A[x][y] = self.A[x][y] >> (((t + 1) * (t + 2) // 2) % self.w) ^ self.A[x][y] << (self.w - (((t + 1) * (t + 2) // 2) % self.w)) & (2 ** self.w - 1)
            x, y = y, (2 * x + 3 * y) % 5

    def _pi(self):
        A_temp = deepcopy(self.A)
        for x in range(5):
            for y in range(5):
                A_temp[x][y] = self.A[(x + 3 * y) % 5][x]
        self.A = A_temp

    def _chi(self):
        A_temp = deepcopy(self.A)
        for x in range(5):
            for y in range(5):
                A_temp[x][y] = self.A[x][y] ^ ((self.A[(x + 1) % 5][y] ^ (2 ** self.w - 1)) & self.A[(x + 2) % 5][y])
        self.A = A_temp

    def _rc(self, t):
        if t % 255 == 0:
            return 1
        R = 0b10000000
        for i in range(t % 255):  # 这里文档写的是 i from 1 to t mod 255,但是这样和测试样例对不上
            R8 = R & 0b00000001
            R >>= 1
            R ^= R8 << 7
            R ^= R8 << 3
            R ^= R8 << 2
            R ^= R8 << 1
        return (R & 0b10000000) >> 7

    def _iota(self, i_r):
        RC = 0
        for j in range(self.l + 1):
            RC |= self._rc(j + 7 * i_r) << (self.w - 1 - (2 ** j - 1))
        self.A[0][0] ^= RC

    def _sponge(self, r, N, d):
        P = N + self._pad_10(r, len(N))
        self._print_intermediate_S('Data to be absorbed', P + '0' * d * 2)
        n = len(P) // r
        c = self.b - r
        p = [0] * n
        for i in range(n):
            p[i] = P[i * r:(i + 1) * r]
        S = '0' * self.b
        for i in range(n):
            S = self._keccak_p(self._bin_xor(S, p[i] + '0' * c, self.b), 12 + 2 * self.l)
        Z = ''
        while 1:
            Z = Z + self._Trunc(S, r)
            if d <= len(Z):
                return self._Trunc(Z, d)
            S = self._keccak_p(S, 12 + 2 * self.l)

    @staticmethod
    def _pad_10(x, m):
        j = (-m - 2) % x
        return '1' + '0' * j + '1'

    def _keccak_p(self, S, n_r):
        self._string_to_state_array(S)
        for i_r in range(12 + 2 * self.l - n_r, 12 + 2 * self.l):
            self.print_intermediate_value('Round #' + str(i_r))
            self._Rnd(i_r)
        return self._state_array_to_string()

    def _string_to_state_array(self, S):
        for x in range(5):
            for y in range(5):
                self.A[x][y] = int(S[self.w * (5 * y + x):self.w * (5 * y + x + 1)], 2)

    def _state_array_to_string(self):
        S = ''
        for y in range(5):
            for x in range(5):
                S += self._int_to_bin(self.A[x][y], self.w)
        return S

    def _Rnd(self, i_r):
        self._theta()
        temp_S = self._state_array_to_string()
        self._print_intermediate_S("After Theta:", temp_S)
        self._rho()
        temp_S = self._state_array_to_string()
        self._print_intermediate_S("After Rho:", temp_S)
        self._pi()
        temp_S = self._state_array_to_string()
        self._print_intermediate_S("After Pi:", temp_S)
        self._chi()
        temp_S = self._state_array_to_string()
        self._print_intermediate_S("After Chi:", temp_S)
        self._iota(i_r)
        temp_S = self._state_array_to_string()
        self._print_intermediate_S("After Iota:", temp_S)

    @staticmethod
    def _Trunc(S, d):
        return S[:d]

    def _bin_xor(self, bit_1, bit_2, out_len):
        result = int(bit_1, 2) ^ int(bit_2, 2)
        return self._int_to_bin(result, out_len)

    @staticmethod
    def _small_endian(P):  # 小端变换
        for i in range(len(P) // 8):
            temp = P[i * 8:(i + 1) * 8]
            P = P[:i * 8] + temp[::-1] + P[(i + 1) * 8:]
        return P

    def _print_intermediate_S(self, text, S):
        self.print_intermediate_value(text)
        hex_list = TypeConvert.int_to_hex_list(int(self._small_endian(S), 2), self.b // 8)
        for i in range(self.b // 8 // 16):
            self.print_intermediate_value('\t' + TypeConvert.hex_list_to_str(hex_list[i * 16:(i + 1) * 16]))
        self.print_intermediate_value('\t' + TypeConvert.hex_list_to_str(hex_list[-(self.b // 8 % 16):]))

    @staticmethod
    def _int_to_bin(num, length):
        str_bin = bin(num)[2:]
        return '0' * (length - len(str_bin)) + str_bin
