import hashlib
import logging
import math
import re

from PyQt5 import QtCore
from Util import TypeConvert

rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

# A B C D
init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
# 非线性函数
functions = 16 * [lambda b, c, d: (b & c) | (~b & d)] + \
            16 * [lambda b, c, d: (d & b) | (~d & c)] + \
            16 * [lambda b, c, d: b ^ c ^ d] + \
            16 * [lambda b, c, d: c ^ (b | ~d)]

index_functions = 16 * [lambda i: i] + \
                  16 * [lambda i: (5 * i + 1) % 16] + \
                  16 * [lambda i: (3 * i + 5) % 16] + \
                  16 * [lambda i: (7 * i) % 16]


# 对x左移amount位
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def filter_space(string):
    string = string.replace(" ", "")
    new_str = ''
    for i in range(len(string)):
        if i % 8 == 0 and i != 0:
            new_str = new_str + ' ' + string[i]
        else:
            new_str = new_str + string[i]
    return new_str


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, message, message_len, key, key_len):
        super(Thread, self).__init__(parent)
        self.message = message
        self.message_len = message_len
        self.key = key
        self.key_len = key_len

    # hash script
    def hash_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Hash begins")
        self.print_intermediate_value("Message:\n" + TypeConvert.int_to_str(self.message, self.message_len))
        self.print_intermediate_value("Key:\n" + TypeConvert.int_to_str(self.key, self.key_len))
        result = self.hmac_hash()
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

    def hmac_hash(self):
        self.key_expand()
        ipad = 0x36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636
        ipad_key = self.key ^ ipad
        self.print_intermediate_value("\nipadkey:" + filter_space(TypeConvert.int_to_str(ipad_key, 64)) + "\n")
        # ipad_key_list = TypeConvert.int_to_hex_list(ipad_key, 64)
        # message_list = TypeConvert.int_to_hex_list(self.message, self.message_len)
        # ipad_key_list.extend(message_list)
        # digest = self.md5(ipad_key_list)
        ipad_key_str = TypeConvert.int_to_str(ipad_key, 64)
        message_str = TypeConvert.int_to_str(self.message, self.message_len)
        digest = hashlib.md5(bytes.fromhex(ipad_key_str + message_str)).hexdigest()

        opad = 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c
        opad_key = self.key ^ opad
        self.print_intermediate_value("\nopadkey:" + filter_space(TypeConvert.int_to_str(opad_key, 64)) + "\n")
        # opad_key_list = TypeConvert.int_to_hex_list(opad_key, 64)
        # tmp_list = TypeConvert.int_to_hex_list(digest, 16)
        # opad_key_list.extend(tmp_list)
        # digest = self.md5(opad_key_list)
        opad_key_str = TypeConvert.int_to_str(opad_key, 64)
        digest = hashlib.md5(bytes.fromhex(opad_key_str + digest)).hexdigest()
        # digest = hashlib.md5(bytes.fromhex(digest)).hexdigest()
        result = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", digest)
        return result.upper()
        # raw = digest.to_bytes(16, byteorder='little')
        # return TypeConvert.int_to_str(int.from_bytes(raw, byteorder='big'), 16)

    # def md5(self, message):
    #     message = bytearray(message)  # copy our input into a mutable buffer
    #     orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
    #     message.append(0x80)
    #     while len(message) % 64 != 56:
    #         message.append(0)
    #     message += orig_len_in_bits.to_bytes(8, byteorder='little')
    #
    #     hash_pieces = init_values[:]
    #     cnt = 0
    #     for chunk_ofst in range(0, len(message), 64):
    #         a, b, c, d = hash_pieces
    #         chunk = message[chunk_ofst:chunk_ofst + 64]
    #         chunk_int = int.from_bytes(chunk, byteorder='big')
    #
    #         self.print_intermediate_value('Fill ' + str(cnt))
    #         cnt += 1
    #
    #         self.print_intermediate_value(filter_space(TypeConvert.int_to_str(chunk_int, 64)))
    #
    #         self.print_intermediate_value('        a          b         c        d')
    #         for i in range(64):
    #             f = functions[i](b, c, d)
    #             g = index_functions[i](i)
    #             to_rotate = a + f + constants[i] + int.from_bytes(chunk[4 * g:4 * g + 4], byteorder='little')
    #             new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
    #             a, b, c, d = d, new_b, b, c
    #             self.print_intermediate_value(
    #                 '%02d' % i + ' 0x' + '{0:08x} '.format(a, '0x').upper() + ' {0:08x} '.format(b, '0x').upper() + ' {0:08x} '.format(
    #                     c, '0x').upper() + ' {0:08x} '.format(d, '0x').upper())
    #
    #         for i, val in enumerate([a, b, c, d]):
    #             hash_pieces[i] += val
    #             hash_pieces[i] &= 0xFFFFFFFF
    #
    #     return sum(x << (32 * i) for i, x in enumerate(hash_pieces))

    def key_expand(self):
        self.print_intermediate_value('Key Expand:')
        if self.key_len < 64:
            self.key *= 16 ** ((64 - self.key_len) * 2)
        elif self.key_len > 64:
            key_str = TypeConvert.int_to_str(self.key, self.key_len)
            digest = hashlib.md5(bytes.fromhex(key_str)).hexdigest()
            self.key = digest.ljust(128, "0")
            self.key = TypeConvert.str_to_int(self.key)
        self.print_intermediate_value('Key:' + filter_space(TypeConvert.int_to_str(self.key, 64)))
