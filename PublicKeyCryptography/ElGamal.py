import logging
import math
import random
from Crypto.PublicKey import RSA
from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str, str, str, str, str)
    M_result = QtCore.pyqtSignal(str)
    C1_C2 = QtCore.pyqtSignal(str, str)

    def __init__(self, parent, mode=0, C1=0, C2=0, x=0, p=0, a=0, y=0, m=0):
        super(Thread, self).__init__(parent)
        self.length = 128
        self.mode = mode
        self.C1 = C1
        self.C2 = C2
        self.x = x
        self.p = p
        self.a = a
        self.y = y
        self.m = m

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
        p = RSA.generate(2048).q
        # 得到α
        while True:
            a = random.randrange(2, p - 1)
            if self.is_prime(a):
                break

        # 得到Alice的私钥XA  1<XA<q-1
        x = random.randrange(2, p - 1)
        # 计算YA  a的XA次方模q
        y = self.pow_mod_n(a, x, p)
        # 生成length字节的随机明文M, 1<=M<=q-1
        m = random.randrange(1, p)
        # 转成16进制的表示
        p = TypeConvert.int_to_str(p, self.length)
        a = TypeConvert.int_to_str(a, self.length)
        x = TypeConvert.int_to_str(x, self.length)
        y = TypeConvert.int_to_str(y, self.length)
        m = TypeConvert.int_to_str(m, self.length)

        self.print_final_result(p, a, x, y, m)

    # 利用扩展的欧几里得算法返回a模m的逆元
    @staticmethod
    def find_mod_reverse(a, m):
        if math.gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m

    # q,a,YA,M
    def encrypt(self):
        k = random.randrange(1, self.p)
        C1 = self.pow_mod_n(self.a, k, self.p)
        private_key = self.pow_mod_n(self.y, k, self.p)
        C2 = (private_key * self.m) % self.p
        self.print_C1_C2(TypeConvert.int_to_str(C1, self.length), TypeConvert.int_to_str(C2, self.length))

    def decrypt(self):
        # 计算
        K = self.pow_mod_n(self.C1, self.x, self.p)
        #
        K1 = self.find_mod_reverse(K, self.p)
        M = (self.C2 * K1) % self.p
        self.print_M(TypeConvert.int_to_str(M, self.length))

    def print_final_result(self, text1, text2, text3, text4, text5):
        self.final_result.emit(text1, text2, text3, text4, text5)

    def print_M(self, M):
        self.M_result.emit(M)

    def print_C1_C2(self, C1, C2):
        self.C1_C2.emit(C1, C2)

    # execute this function after start function executed
    def run(self):
        # 生成参数
        if self.mode == 0:
            self.generate_run()
        # 解密
        elif self.mode == 1:
            self.decrypt()
        # 加密
        elif self.mode == 2:
            self.encrypt()
