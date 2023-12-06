import math
from .Prepare import hash_function, PRG_function, KDF
from . import config
from .Point import Point
from .SM2_Code import bytes_to_bits, ele_to_bytes, point_to_bytes, bits_to_bytes, bytes_to_point
from .SM2_ECG import ECG_k_point, ECG_ele_zero
from .binary import padding_0_to_length, remove_0b_at_beginning


def kp(k, Point):
    return ECG_k_point(k, Point)


# 判断a是否为全0比特串
def is_zero_bits(a):
    for i in a:
        if i != '0':
            return False
    return True


def Encryption(M, PB):
    q = config.get_q()
    n = config.get_n()
    Gx = config.get_Gx()
    Gy = config.get_Gy()
    h = config.get_h()
    klen = len(M)
    t = '000000'
    while is_zero_bits(t):
        # A1：用随机数发生器产生随机数k∈[1,n-1]
        k = PRG_function(1, n - 1)
        # A2.1：计算椭圆曲线点C1=[k]G=(x1,y1)
        # A2.2：按本文本第1部分4.2.8和4.2.4给出的细节，将C1的数据类型转换为比特串
        k = int('4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F'.replace(' ', ''), 16)
        C1 = ECG_k_point(k, Point(Gx, Gy))
        x1 = hex(C1.x)
        y1 = hex(C1.y)
        # print('enc: C1_point', C1)
        C1 = point_to_bytes(C1)
        C1 = bytes_to_bits(C1)
        # A3：计算椭圆曲线点S=[h]PB，若S是无穷远点，则报错并退出
        S = ECG_k_point(h, PB)
        if S == ECG_ele_zero():
            print('*** ERROR: S is infinite point *** function: Decryption ***')
            return -1
        # A4.1：计算椭圆曲线点[k]PB=(x2,y2)
        # A4.2：按本文本第1部分4.2.5和4.2.4给出的细节，将坐标x2、y2的数据类型转换为比特串
        # print("enc: PB = ", PB)
        x2 = ECG_k_point(k, PB).x
        y2 = ECG_k_point(k, PB).y
        x2 = bytes_to_bits(ele_to_bytes(x2))
        y2 = bytes_to_bits(ele_to_bytes(y2))
        x2 = remove_0b_at_beginning(x2)
        y2 = remove_0b_at_beginning(y2)
        # A5：计算t=KDF(x2 ∥y2, klen)，若t为全0比特串，则返回A1
        t = KDF(x2 + y2, klen)
    # A6：计算C2 = M ⊕t
    M = remove_0b_at_beginning(M)
    C2 = bin(int(M, 2) ^ int(t, 2))
    C2 = padding_0_to_length(C2, klen)
    # A7：计算C3 = Hash(x2 ∥ M ∥ y2)
    C3 = hash_function(x2 + M + y2)
    # A8：输出密文C = C1 ∥ C2 ∥ C3
    C1 = remove_0b_at_beginning(C1)
    C2 = remove_0b_at_beginning(C2)
    C3 = remove_0b_at_beginning(C3)
    # print('enc: len_C1', len(C1))
    # print('enc: len_C2', len(C2))
    # print('enc: len_C3', len(C3))

    # print('enc: C1', C1)
    # print('enc: C2', C2)
    # print('enc: C3', C3)
    C = C1 + C2 + C3
    return C


### test Encryption ###
'''
# 密钥对生成
config.default_config()
parameters = config.get_parameters()
key = key_pair_generation(parameters)
dB = key[0]
PB = key[1]

config.set_q(211)
config.set_a(0)
config.set_b(207)
#point = Point('0b100000000', '0b100000000')
#print(point_to_bytes(point))
q = config.get_q()
n = 10
G = Point(2, 2)
#PB = Point(115, 48)
v = 256
M = '101001010110001010000000000000000000001010101010101010'
C = Encryption(M, PB)
'''


def Decryption(C, dB):
    a = config.get_a()
    b = config.get_b()
    q = config.get_q()
    h = config.get_h()
    l = math.ceil(math.log(q, 2) / 8)
    # B1.1：从C中取出比特串C1
    # B1.2：按本文本第1部分4.2.3和4.2.9给出的细节，将C1的数据类型转换为椭圆曲线上的点
    # B1.3：验证C1是否满足椭圆曲线方程，若不满足则报错并退出
    C1 = C[0:(1 + l * 2) * 8]
    C2 = C[(1 + l * 2) * 8:len(C) - 256]
    C3 = C[len(C) - 256:len(C)]
    C1 = '0b' + C1
    # print('dec: length of C1', len(bits_to_bytes(C1)))
    # print('dec: C1', bits_to_bytes(C1))
    # print('dec: C2', C2)
    # print('dec: C3', C3)
    # print('dec: l value', l)
    C1 = bytes_to_point(a, b, bits_to_bytes(C1))
    # B2：计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出
    S = ECG_k_point(h, C1)
    if S == ECG_ele_zero():
        print('*** ERROR: S is infinite point *** function: Decryption ***')
        return -1
    # B3.1：计算[dB]C1=(x2,y2)
    # B3.2：按本文本第1部分4.2.5和4.2.4给出的细节，将坐标x2、y2的数据类型转换为比特串
    x2 = ECG_k_point(dB, C1).x
    y2 = ECG_k_point(dB, C1).y
    x2 = bytes_to_bits(ele_to_bytes(x2))
    y2 = bytes_to_bits(ele_to_bytes(y2))
    # B4：计算t=KDF(x2 ∥y2, klen)，若t为全0比特串，则报错并退出
    klen = len(C2)
    x2 = remove_0b_at_beginning(x2)
    y2 = remove_0b_at_beginning(y2)
    t = KDF(x2 + y2, klen)
    if is_zero_bits(t):
        print("*** ERROR: t为全0比特串 *** function: Decryption ***")
        return -1
    # B5：从C中取出比特串C2，计算M′ = C2 ⊕t
    M_ = bin(int(C2, 2) ^ int(t, 2))
    M_ = padding_0_to_length(M_, klen)
    # B6：计算u = Hash(x2 ∥ M′ ∥ y2)，从C中取出比特串C3，若u ̸= C3，则报错并退出
    x2 = remove_0b_at_beginning(x2)
    M_ = remove_0b_at_beginning(M_)
    y2 = remove_0b_at_beginning(y2)
    u = hash_function(x2 + M_ + y2)
    if remove_0b_at_beginning(u) != remove_0b_at_beginning(C3):
        print("*** ERROR: u不等于C3 *** function: Decryption ***")
    # return -1
    # B7：输出明文M′
    return M_


### test ###
# dB = 121
'''
M_ = Decryption(C)
print('M ', M)
print('C ', C)
print('M_', M_)
'''
