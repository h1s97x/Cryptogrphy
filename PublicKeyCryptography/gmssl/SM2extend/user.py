# coding=utf-8
from . import SM2_Encryption as Encryption
from . import api
from .Point import Point


def kp(k, g_hexstr):
    api.SM2_init('')
    # k=int('4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F'.replace(' ',''),16)
    gx = g_hexstr[0:int(len(g_hexstr) / 2)]
    gy = g_hexstr[int(len(g_hexstr) / 2):int(len(g_hexstr))]
    # C1=Encryption.kp(k,Point(int('0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D',16),
    #                          int('0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2',16)))
    C1 = Encryption.kp(k, Point(int(gx, 16), int(gy, 16)))
    # PC='04'
    x1 = hex(C1.x).replace('0x', '')
    x1 = '0' * (64 - len(x1)) + x1
    y1 = hex(C1.y).replace('0x', '')
    y1 = '0' * (64 - len(y1)) + y1
    return x1 + y1

# api.SM2_init('')
# k=int('4C62EEFD 6ECFC2B9 5B92FD6C 3D957514 8AFA1742 5546D490 18E5388D 49DD7B4F'.replace(' ',''),16)
# # gx=g_hexstr[0:int(len(g_hexstr)/2)]
# # gy = g_hexstr[int(len(g_hexstr) / 2):int(len(g_hexstr))]
# C1=Encryption.kp(k,Point(int('0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D',16),
#                          int('0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2',16)))
# # C1 = Encryption.kp(k, Point(int(gx,16),int(gy,16)))
# PC='04'
# x1=hex(C1.x).replace('0x','')
# y1=hex(C1.y).replace('0x','')
# tmp=1


#
# while True:
#         api.SM2_key_pair_gen()
#         print("密钥对生成完毕")
#         break
# q = False
# result = ''
# while not q:
#     data = ''
#     while True:
#             data = input("输入字符串内容（不输入表示使用上次计算结果作为输入）：")
#             if data == '':
#                 data = result
#             break
#     while True:
#         ed = input("输入 e 进行加密， 输入 d 进行解密， 输入 q 退出：")
#         if ed == 'q':
#             q = True
#             break
#         elif ed == 'e':
#             api.SM2_read_public_key(pkname)
#
#             result = api.SM2_encrypt_str(str(data), pkname)
#
#             # pk = api.SM2_read_public_key(pkname)
#             # result= api.Enc_Interface(str(data), pk)
#             print("加密结果：" + result)
#             # else:
#             #     api.SM2_encrypt_file(data, pkname)
#             #     print("加密完毕")
#             break
#         elif ed == 'd':
#             api.SM2_read_private_key(skname)
#             result = api.SM2_decrypt_str(str(data), skname)
#             print("解密结果：" + result)
#             break
#         else:
#             print("错误的参数，请重新输入")
#             continue
