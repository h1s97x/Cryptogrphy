import logging
import random

from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    pars = QtCore.pyqtSignal(str, str)
    xa = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str, str, str, str, str)
    is_finished = QtCore.pyqtSignal()

    def __init__(self, parent, length, opt):
        super(Thread, self).__init__(parent)
        self.length = int(length)
        self.opt = int(opt)

    # 检测大整数是否是素数,如果是素数,就返回True,否则返回False
    @staticmethod
    def rabin_miller(num):
        s = num - 1
        t = 0
        while s % 2 == 0:
            s //= 2
            t += 1

        for trials in range(5):
            a = random.randrange(2, num - 1)
            v = pow(a, s, num)
            if v != 1:
                i = 0
                while v != (num - 1):
                    if i == t - 1:
                        return False
                    else:
                        i += 1
                        v = (v ** 2) % num
        return True

    def is_prime(self, num):
        # 排除0,1和负数
        if num < 2:
            return False
        # 创建小素数的列表,可以大幅加快速度
        # 如果是小素数,那么直接返回true
        small_primes = \
            [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
             101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
             211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
             307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
             401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
             503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
             601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
             701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
             809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
             907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
        if num in small_primes:
            return True
        # 如果大数是这些小素数的倍数,那么就是合数,返回false
        for prime in small_primes:
            if num % prime == 0:
                return False
        # 如果这样没有分辨出来,就一定是大整数,那么就调用rabin算法
        return self.rabin_miller(num)

    # 得到大整数,和Key-length长度相同
    def get_prime(self, size):
        while True:
            num = random.randrange(2 ** (size - 1), 2 ** size)
            if self.is_prime(num):
                return num

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
        logging.info("thread running")
        # 得到大素数p
        while True:
            q = self.get_prime(8 * self.length - 1)
            p = 2 * q + 1
            if self.is_prime(p):
                break
        # 得到p的本原根a
        while True:
            a = random.randrange(2, p - 1)
            a_pow2 = self.pow_mod_n(a, 2, p)
            a_pow_q = self.pow_mod_n(a, q, p)
            if (a_pow2 != 1) and (a_pow_q != 1):
                break
        p = TypeConvert.int_to_str(p, self.length)
        a = TypeConvert.int_to_str(a, self.length)
        self.print_pars(p, a)

    def print_pars(self, p, a):
        self.pars.emit(p, a)

    # execute this function after start function executed
    def run(self):
        if self.opt == 0:
            self.generate_run()
        else:
            self.gen_xa_run()
