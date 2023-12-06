import binascii
import logging
from math import ceil
from PyQt5 import QtCore
from Util import TypeConvert

rotl = lambda x, n: ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)
bytes_to_list = lambda data: [i for i in data]

IV = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]

T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]


def sm3_ff_j(x, y, z, j):
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret


def sm3_gg_j(x, y, z, j):
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        # ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret


def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))


def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))


def hex_list_to_str_4(hex_list):
    str_all = TypeConvert.hex_list_to_str(hex_list).replace(" ", "")
    str_4 = ''
    i_count = 0
    length = len(str_all) // 8
    for i in range(length):
        i_count += 1
        str_4 += str_all[i * 8:(i + 1) * 8] + " "
        if i_count == 8:
            str_4 += '\n'
            i_count = 0
    str_4 += str_all[length * 8:]
    return str_4


def int_64_to_str_4(int_list):
    hex_str = ''
    i_count = 0
    for i in int_list:
        i_count += 1
        hex_str += TypeConvert.int_to_str(i, 4).replace(" ", "") + " "
        if i_count == 8:
            hex_str += "\n"
            i_count = 0
    return hex_str.strip()


def int_64_to_str(int_list):
    hex_str = ''
    for i in int_list:
        hex_str += TypeConvert.int_to_str(i, 4) + " "
    return hex_str.strip()


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text):
        super(Thread, self).__init__(parent)
        self.input_text = input_text

    # hash script
    def hash_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Hash begins*****************************/")
        self.print_intermediate_value("\nMessage:\n" + hex_list_to_str_4(self.input_text))
        result = self.sm3_hash(self.input_text)
        self.print_intermediate_value("\nHashed:\n" + int_64_to_str_4(result))
        self.print_intermediate_value("\nHash completed\n")
        self.print_final_result(int_64_to_str(result))

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.hash_run()

    def sm3_cf(self, v_i, b_i):
        w = []
        for i in range(16):
            weight = 0x1000000
            data = 0
            for k in range(i * 4, (i + 1) * 4):
                data = data + b_i[k] * weight
                weight = int(weight / 0x100)
            w.append(data)

        for j in range(16, 68):
            w.append(0)
            w[j] = sm3_p_1(w[j - 16] ^ w[j - 9] ^ (rotl(w[j - 3], 15 % 32))) ^ (rotl(w[j - 13], 7 % 32)) ^ w[j - 6]

        # 显示w0w1...w67
        self.print_intermediate_value("w0w1...w67:")
        self.print_intermediate_value(int_64_to_str_4(w))

        w_1 = []
        for j in range(0, 64):
            w_1.append(0)
            w_1[j] = w[j] ^ w[j + 4]

        # 显示w0'w1'...w63'
        self.print_intermediate_value("\nw0'w1'...w63':")
        self.print_intermediate_value(int_64_to_str_4(w_1))

        a, b, c, d, e, f, g, h = v_i
        v_j = [a, b, c, d, e, f, g, h]
        self.print_intermediate_value("\nhash intermediate value:")
        self.print_intermediate_value(
            "          A        B        C        D        E        F        G        H")
        self.print_intermediate_value("       " + int_64_to_str_4(v_j))

        for j in range(0, 64):
            ss_1 = rotl(
                ((rotl(a, 12 % 32)) +
                 e +
                 (rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
            )
            ss_2 = ss_1 ^ (rotl(a, 12 % 32))
            tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
            tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
            d = c
            c = rotl(b, 9 % 32)
            b = a
            a = tt_1
            h = g
            g = rotl(f, 19 % 32)
            f = e
            e = sm3_p_0(tt_2)

            a, b, c, d, e, f, g, h = map(
                lambda x: x & 0xFFFFFFFF, [a, b, c, d, e, f, g, h])

            v_j = [a, b, c, d, e, f, g, h]
            self.print_intermediate_value(f'{j:^#5}' + "  " + int_64_to_str_4(v_j))

        return [v_j[i] ^ v_i[i] for i in range(8)]

    def sm3_hash(self, msg):
        len1 = len(msg)
        reserve1 = len1 % 64
        msg.append(0x80)
        reserve1 += 1
        # 56-64, add 64 byte
        range_end = 56
        if reserve1 > range_end:
            range_end += 64

        for i in range(reserve1, range_end):
            msg.append(0x00)

        bit_length = len1 * 8
        bit_length_str = [bit_length % 0x100]
        for i in range(7):
            bit_length = int(bit_length / 0x100)
            bit_length_str.append(bit_length % 0x100)
        for i in range(8):
            msg.append(bit_length_str[7 - i])

        group_count = round(len(msg) / 64)

        self.print_intermediate_value("")
        self.print_intermediate_value("Fill " + str(group_count) + ":")
        self.print_intermediate_value(hex_list_to_str_4(msg))

        B = []
        for i in range(0, group_count):
            B.append(msg[i * 64:(i + 1) * 64])

        V = [IV]
        for i in range(0, group_count):
            self.print_intermediate_value("\nThe No." + str(i) + " block:")
            V.append(self.sm3_cf(V[i], B[i]))

        return V[i + 1]

    def sm3_kdf(self, z, k_len):  # z为16进制表示的比特串（str），k_len为密钥长度（单位byte）
        k_len = int(k_len)
        ct = 0x00000001
        rcnt = ceil(k_len / 32)
        zin = [i for i in bytes.fromhex(z.decode('utf8'))]
        ha = ""
        for i in range(rcnt):
            msg = zin + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
            ha += self.sm3_hash(msg)
            ct += 1
        return ha[0: k_len * 2]
