import math
from . import SM2_Code


# 多项式加法单位元 #
def polynomial_zero():
    return '0b0'


# 多项式乘法单位元 #
def polynomial_one():
    return '0b1'


# 多项式乘法 #
'''
input: 两个多项式（比特串）
output: 两个多项式的乘积
'''


def polynomial_times(a, b):
    # print("--- 多项式 乘法 ---")

    a_bytes = SM2_Code.bits_to_bytes(a)
    a_int = SM2_Code.bytes_to_int(a_bytes)
    b_bytes = SM2_Code.bits_to_bytes(b)
    b_int = SM2_Code.bytes_to_int(b_bytes)

    # max result length
    m = len(a) - 2 + len(b) - 2
    m_bytes = math.ceil(float(m) / 8.0)

    # counter
    i = 0
    # result
    c = 0
    while a_int != 0:
        if a_int % 2 == 1:
            c = c ^ (b_int << i)
        a_int //= 2
        i += 1
    return SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(c, m_bytes))


# test polynomial_times #
# print(polynomial_times('0b111', '0b11111001'))

# 多项式除法 #

'''
input: 被除多项式 a 和除多项式 b
output: a/b
'''


def polynomial_a_devide_b(a, b):
    # print("--- 多项式 除法 ---")

    a_bytes = SM2_Code.bits_to_bytes(a)
    a_int = SM2_Code.bytes_to_int(a_bytes)
    a_len = len(a_bytes)
    b_bytes = SM2_Code.bits_to_bytes(b)
    b_int = SM2_Code.bytes_to_int(b_bytes)
    b_len = len(b_bytes)

    # max result length
    m = len(a) - 2
    m_bytes = math.ceil(float(m) / 8.0)

    c = 0
    i = len(a) - len(b)
    while i >= 0:
        a_int = a_int ^ (b_int << i)
        c += (1 << i)
        i = len(SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(a_int, a_len))) \
            - len(SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(b_int, b_len)))
    return SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(c, m_bytes))


### test polynomial_a_devide_b ###
# print(polynomial_a_devide_b('0b1101101001110', '0b111011'))
# print(polynomial_a_devide_b('0b1011101110', '0b111'))

# 多项式取模 #
'''
input: 被除多项式 a 和除多项式 b
output: a/b 所余的多项式
'''


def polynomial_a_mod_b(a, b):
    # print("--- 多项式 取模 ---")

    a_bytes = SM2_Code.bits_to_bytes(a)
    a_int = SM2_Code.bytes_to_int(a_bytes)
    a_len = len(a_bytes)
    b_bytes = SM2_Code.bits_to_bytes(b)
    b_int = SM2_Code.bytes_to_int(b_bytes)
    b_len = len(b_bytes)

    # max result length
    m = len(b) - 1
    m_bytes = math.ceil(float(m) / 8.0)

    i = len(a) - len(b)
    while i >= 0:
        a_int = a_int ^ (b_int << i)
        i = len(SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(a_int, a_len))) \
            - len(SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(b_int, b_len)))

    return SM2_Code.bytes_to_bits(SM2_Code.int_to_bytes(a_int, m_bytes))
### test polynomial_a_mod_b ###
# print(polynomial_a_mod_b('0b1011101110', '0b111'))
