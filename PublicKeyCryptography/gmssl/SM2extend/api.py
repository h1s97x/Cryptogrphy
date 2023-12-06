from .Interface import keyEX_Interface_1, Dec_Interface, Enc_Interface, keyEX_Interface_2, keyEX_Interface_get_ZA_ZB, \
    Sig_Interface, Ver_Interface
from . import config
from .SM2_ECG import key_pair_generation
from .SM2_Code import bytes_to_str, point_to_bytes, bytes_to_point, str_to_bytes


# 初始化椭圆曲线参数 #
def SM2_init(filename=''):
    if filename == '':
        config.default_config()
    else:
        parameters = config.read_config_file(filename)
        config.set_parameters(parameters)


# 产生密钥对 #
def SM2_key_pair_gen():
    pk_file = 'public_key'
    sk_file = 'private_key'
    param = config.get_parameters()
    key_pair = key_pair_generation(param)
    # print("私钥： " + str(key_pair[0]))
    # print("公钥： ")
    # print(key_pair[1])
    sk = config.get_parameters()
    sk['private key'] = key_pair[0]
    pk = config.get_parameters()
    pk['public key'] = bytes_to_str(point_to_bytes(key_pair[1]))

    fo = open(sk_file, "w", encoding='utf-8')
    fo.write(str(sk))
    fo.close()
    fo = open(pk_file, "wb")
    fo.write(bytes(str(pk), encoding='utf-8'))
    fo.close()


### test key_pair_gen ###
# SM2_init()
# SM2_key_pair_gen()

# 读取公钥文件 #
def SM2_read_public_key(filename):
    parameters = config.read_config_file(filename)
    config.set_parameters(parameters)
    a = config.get_a()
    b = config.get_b()
    return bytes_to_point(a, b, str_to_bytes(parameters['public key']))


# 读取私钥文件 #
def SM2_read_private_key(filename):
    parameters = config.read_config_file(filename)
    config.set_parameters(parameters)
    return parameters['private key']


# 加密文件 #
def SM2_encrypt_file(in_file, public_key_file, out_file=''):
    # 读公钥
    pk = SM2_read_public_key(public_key_file)
    # 读文件内容
    fo = open(in_file, "ab+")
    fl = fo.tell()
    fo.seek(0, 0)
    m = fo.read(fl)
    fo.close()
    # 加密内容
    c = Enc_Interface(str(m, encoding='utf-8'), pk)
    # 写入输出文件
    if out_file == '':
        out_file = in_file + '.sm2'
    else:
        out_file += '.sm2'
    fo = open(out_file, "wb")
    fo.write(bytes(c, encoding='utf-8'))
    fo.close()


# 解密文件 #
def SM2_decrypt_file(in_file, private_key_file, out_file=''):
    # 读私钥
    sk = SM2_read_private_key(private_key_file)
    # 读文件内容
    sl = len(in_file)
    if in_file[sl - 4: sl] != '.sm2':
        print("错误：不正确的文件后缀名（应为'.sm2'）")
        return False
    fo = open(in_file, "ab+")
    fl = fo.tell()
    fo.seek(0, 0)
    c = fo.read(fl)
    fo.close()
    # 解密内容
    m = Dec_Interface(str(c, encoding='utf-8'), sk)
    # 写入输出文件
    if out_file == '':
        out_file = in_file[0: sl - 4]
    fo = open(out_file, "wb")
    fo.write(bytes(m, encoding='utf-8'))
    fo.close()
    return True


### test SM2_encrypt_file and SM2_decrypt_file ###
'''
SM2_init()
SM2_key_pair_gen()
SM2_encrypt_file("platText", "public_key", "yes")
SM2_decrypt_file("yes.sm2", "public_key")
'''


# 加密字符串 #
def SM2_encrypt_str(data, public_key_file):
    # 读公钥
    pk = SM2_read_public_key(public_key_file)
    return Enc_Interface(data, pk)


# 解密字符串 #
def SM2_decrypt_str(data, private_key_file):
    sk = SM2_read_private_key(private_key_file)
    return Dec_Interface(data, sk)


### test SM2_encrypt_str and SM2_decrypt_str ###
'''
SM2_init()
SM2_key_pair_gen()
c = SM2_encrypt_str("hello world!", "public_key")
print("密文：" + c)
m = SM2_decrypt_str(c, "private_key")
print("解密结果： " + m)
'''

# DH 密钥交换 #
# 字符串输入 #
'''
input: 
    priv    私钥
    pub     公钥
    klen    协商的密钥长度
output:
    密钥
'''


def SM2_gen_EXkey_s():
    return keyEX_Interface_1()


def SM2_gen_EXkey_f(priv, pub):
    fo = open(priv, 'w')
    pk, sk = keyEX_Interface_1()
    fo.write(str(sk))
    fo.close()
    fo = open(pub, 'w')
    fo.write(str(pk.x) + '\n')
    fo.write(str(pk.y))
    fo.close()


def SM2_ageed_key_s(iid, oid, ir, iR, oR, ipriv, ipubk, opubk, klen):
    ZA, ZB = keyEX_Interface_get_ZA_ZB(iid, oid, ipubk, opubk)
    sharedKey, _, _ = keyEX_Interface_2(ZA, ZB, ir, iR, oR, ipriv, ipubk, opubk, klen, 1)
    return sharedKey


# 文件输入 #
def SM2_agreed_key_f(priv, pubk, klen):
    pass


### test SM2_gen_EXkey_f ###
'''
SM2_init()
SM2_key_pair_gen()
dA = SM2_read_private_key("private_key")
PA = SM2_read_public_key('public_key')
SM2_key_pair_gen()
dB = SM2_read_private_key("private_key")
PB = SM2_read_public_key('public_key')
IDA = 'ALICE123@YAHOO.COM'
IDB = 'BILL456@YAHOO.COM'
RA, rA = SM2_gen_EXkey_s()
RB, rB = SM2_gen_EXkey_s()
klen = 128
print("A key")
print(SM2_ageed_key_s(IDA, IDB, rA, RA, RB, dA, PA, PB, klen))
print("B key")
print(SM2_ageed_key_s(IDB, IDA, rB, RB, RA, dB, PB, PA, klen))
'''

# 数字签名 #
'''
input:
    priv    私钥文件路径
    pub     公钥文件路径
    id      用户唯一标识符
    m       对字符串操作时为待签名字符串，对文件操作时为文件路径
    sig     待验证的签名
output:
    签名操作返回签名结果，验证操作返回签名的验证结果
'''


# 对字符串签名 #
def SM2_sig_s(priv, pub, id, m):
    pk = SM2_read_public_key(pub)
    sk = SM2_read_private_key(priv)
    return Sig_Interface(m, id, sk, pk)


# 对文件签名 #
def SM2_sig_f(priv, pub, id, m):
    # get file data
    fo = open(m, 'rb')
    fl = fo.tell()
    fo.seek(0, 0)
    data = fo.read(fl)
    fo.close()

    # calculate signature
    pk = SM2_read_public_key(pub)
    sk = SM2_read_private_key(priv)
    return Sig_Interface(str(data, encoding='utf-8'), id, sk, pk)


# 对字符串认证 #
def SM2_ver_s(pub, sig, id, m):
    pk = SM2_read_public_key(pub)
    return Ver_Interface(m, sig, id, pk)


# 对文件认证 #
def SM2_ver_f(pub, sig, id, m):
    # get file data
    fo = open(m, 'rb')
    fl = fo.tell()
    fo.seek(0, 0)
    data = fo.read(fl)
    fo.close()

    # verify signature
    pk = SM2_read_public_key(pub)
    return Ver_Interface(str(data, encoding='utf-8'), sig, id, pk)


### test SM2_sig_s and SM2_ver_s ###
'''
SM2_init()
SM2_key_pair_gen()
idA = 'Alice@mail.com'
sigM = SM2_sig_s('private_key', 'public_key', idA, 'hello world')
print('signature of \'hello world \' from Alice@mail.com')
print(sigM)
print('verify this signature')
print(SM2_ver_s('public_key', sigM, idA, 'hello world'))
'''

### test SM2_sig_f and SM2_ver_f ###
'''
SM2_init()
SM2_key_pair_gen()
filename = 'sig_test_data'
fo = open(filename, 'w')
fo.write('hello world')
fo.close()
idA = 'Alice@mail.com'
sigM = SM2_sig_f('private_key', 'public_key', idA, filename)
print("signature of this file from Alice@mail.com")
print(sigM)
print('verify this signature')
print(SM2_ver_f('public_key', sigM, idA, filename))
'''
