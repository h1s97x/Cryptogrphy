from .Integer import inverse
from .Prepare import get_Z, hash_function, PRG_function
from . import config
import math
from .Point import Point
from .SM2_ECG import ECG_k_point, ECG_ele_add
from .SM2_Code import bytes_to_int, bits_to_bytes, ele_to_bytes, int_to_bytes


def Signature(M, IDA, dA, PA):
    a = config.get_a()
    b = config.get_b()
    n = config.get_n()
    Gx = config.get_Gx()
    Gy = config.get_Gy()
    ZA = get_Z(IDA, PA)
    # A1：置M=ZA ∥ M
    M_ = ZA + M
    # A2：计算e = Hv(M)，按本文本第1部分4.2.3和4.2.2给出的细节将e的数据类型转换为整数
    e = hash_function(M_)
    e = bytes_to_int(bits_to_bytes(e))
    r = 0
    k = 0
    while r == 0 or r + k == n:
        # A3：用随机数发生器产生随机数k ∈[1,n-1]
        k = PRG_function(1, n - 1)
        # A4：计算椭圆曲线点(x1,y1)=[k]G，按本文本第1部分4.2.7给出的细节将x1的数据类型转换为整 数
        x1 = ECG_k_point(k, Point(Gx, Gy)).x
        x1 = bytes_to_int(ele_to_bytes(x1))
        # A5：计算r=(e+x1) modn，若r=0或r+k=n则返回A3
        r = (e + x1) % n
    # A6：计算s = ((1 + dA)−1 ·(k−r·dA)) modn，若s=0则返回A3
    s = (inverse(1 + dA, n) * (k - r * dA)) % n
    # A7：按本文本第1部分4.2.1给出的细节将r、s的数据类型转换为字节串，消息M 的签名为(r,s)。
    # Sig = Point(int_to_bytes(r, math.ceil(n/256)), int_to_bytes(s, math.ceil(n/256)))
    # Sig = Point(int_to_bytes(r, math.ceil(math.log(n, 2)/8)), int_to_bytes(s, math.ceil(math.log(n, 2)/8)))
    r = int_to_bytes(r, math.ceil(math.log(n, 2) / 8))
    s = int_to_bytes(s, math.ceil(math.log(n, 2) / 8))
    Sig = r
    for i in s:
        Sig.append(i)
    return Sig


def Verification(M, Sig, IDA, PA):
    a = config.get_a()
    b = config.get_b()
    n = config.get_n()
    Gx = config.get_Gx()
    Gy = config.get_Gy()
    ZA = get_Z(IDA, PA)
    r = Sig[0:int(len(Sig) / 2)]
    s = Sig[int(len(Sig) / 2): len(Sig)]
    r = bytes_to_int(r)
    s = bytes_to_int(s)
    if r < 1 or r > n - 1 or s < 1 or s > n - 1:
        # print("wrong signature: r,s wrong range")
        return False
    M_ = ZA + M
    e = hash_function(M_)
    e = bytes_to_int(bits_to_bytes(e))
    t = (r + s) % n
    if t == 0:
        # print("wrong signature : t is 0")
        return False

    x1 = ECG_ele_add(ECG_k_point(s, Point(Gx, Gy)), ECG_k_point(t, PA)).x
    R = (e + x1) % n
    if R != r:
        # print("wrong signature: R unequal r")
        return False
    return True


'''
### test Signature ###
config.default_config()
parameters = config.get_parameters()
key = key_pair_generation(parameters)
dA = key[0]
PA = key[1]
IDA = 'ALICE123@YAHOO.COM'
M = '100'
Sig = Signature(M, IDA, dA, PA)
print(Sig)

### test Verification ###
Verification(M, Sig, IDA, dA, PA)

#print('ECG_k_point(2, PA)', ECG_k_point(2, Point(2,2)))
#print('ECG_ele_add( ECG_k_point(1, PA), ECG_k_point(2, PA) )', ECG_k_point(4, ECG_k_point(2, Point(2,2))))
#print('ECG_k_point(3, PA)', ECG_k_point(8, Point(2,2)))	
'''
