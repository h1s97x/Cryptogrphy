import hashlib
import math
from random import randint
from . import config
from . import binary
from . import SM2_Code


# hash函数
def hash_function(m):
    sha256 = hashlib.sha256()
    sha256.update(m.encode("utf8"))
    sha256 = bin(int(sha256.hexdigest(), 16))
    sha256 = binary.padding_0_to_length(sha256, 32 * 8)
    return sha256


# test hash_function #
# print('1--',hash_function('akjkSsd'))
# print('2--',hash_function('asd'))
# print('3--',hash_function('100000000101100001101100000000'))

# 密钥派生函数
'''
input：比特串Z，整数klen(表示要获得的密钥数据的比特长度，要求该值小于(2^32-1)*v)
output：长度为klen的密钥数据比特串K
'''


def KDF(Z, klen):
    v = config.get_v()
    if klen < (2 ** 32 - 1) * v:
        ct = 0x00000001
        H = []
        for i in range(0, math.ceil(klen / v)):
            H.append(binary.remove_0b_at_beginning(hash_function(Z + str(ct))))
            ct += 1
        if klen / v == math.ceil(klen / v):
            H_ = binary.remove_0b_at_beginning(H[math.ceil(klen / v) - 1])
        else:
            H_ = binary.remove_0b_at_beginning(H[math.ceil(klen / v) - 1][0:(klen - (v * math.floor(klen / v)))])
        K = ''
        for i in range(0, math.ceil(klen / v)):
            if i != math.ceil(klen / v) - 1:
                K = K + H[i]
            else:
                K = K + H_
    else:
        print("*** ERROR: klen要小于(2^32-1)*v *** function: KDF(Z, klen) ***")
    return K


# test KDF(Z,klen) #
# v = 256
# print('KDF result', KDF('1101', 10))

def PRG_function(a, b):
    return randint(a, b)


def get_Z(ID, PA):
    a = config.get_a()
    a = SM2_Code.bytes_to_bits(SM2_Code.ele_to_bytes(a))
    b = config.get_b()
    b = SM2_Code.bytes_to_bits(SM2_Code.ele_to_bytes(b))
    n = config.get_n()
    Gx = config.get_Gx()
    Gx_ = SM2_Code.bytes_to_bits(SM2_Code.ele_to_bytes(Gx))
    Gy = config.get_Gy()
    Gy_ = SM2_Code.bytes_to_bits(SM2_Code.ele_to_bytes(Gy))

    ID = SM2_Code.bytes_to_bits(SM2_Code.str_to_bytes(ID))
    ENTL = SM2_Code.int_to_bytes(math.ceil((len(ID) - 2) / 8) * 8, 2)
    ENTL = SM2_Code.bytes_to_bits(ENTL)
    xA = SM2_Code.bytes_to_bits(SM2_Code.ele_to_bytes(PA.x))
    yA = SM2_Code.bytes_to_bits(SM2_Code.ele_to_bytes(PA.y))
    ZA = hash_function(ENTL + ID + a + b + Gx_ + Gy_ + xA + yA)
    return ZA


# test get_Z #
# ID = 'ALICE123@YAHOO.COM'
# ID = 'BILL456@YAHOO.COM'
# ID = str_to_bytes(ID)
# ID = bytes_to_bits(ID)
# print(ID)
# ENTL = int_to_bytes(math.ceil((len(ID)-2)/8)*8, 2)
# ENTL = bytes_to_bits(ENTL)
# print(ENTL)


def M_to_bits(input_M):
    M = ''
    if type(input_M) == type('a'):
        for i in input_M:
            temp = int.from_bytes(i.encode('ascii'), byteorder='big', signed=True)
            temp = SM2_Code.int_to_bytes(temp, 1)
            temp = binary.remove_0b_at_beginning(SM2_Code.bytes_to_bits(temp))
            temp = binary.padding_0_to_length(temp, 8)
            M = M + temp
    if type(input_M) == type([]):
        for i in input_M:
            if type(i) == type('a'):
                for _ in i:
                    temp = int.from_bytes(i.encode('ascii'), byteorder='big', signed=True)
                    temp = SM2_Code.int_to_bytes(temp, 1)
                    temp = binary.remove_0b_at_beginning(SM2_Code.bytes_to_bits(temp))
                    temp = binary.padding_0_to_length(temp, 8)
                    M = M + temp
            elif type(i) == type(0):
                M = binary.remove_0b_at_beginning(SM2_Code.bytes_to_bits(input_M))
                M = binary.padding_0_to_length(M, 8 * math.ceil(len(M) / 8))
            else:
                print('*** ERROR: 字节串中类型不为str或者int *** function：M_to_bits(input) ***')
    return M


# test M_to_bits #
# print(M_to_bits(['aa', 's']))

def bits_to_M(M):
    M = '0b' + M
    M = SM2_Code.bits_to_bytes(M)
    output = SM2_Code.bytes_to_str(M)
    return output
# test bits_to_M #
# print(bits_to_M('011000010110000101110011'))
