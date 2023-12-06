
"""=================================================
@Project -> File   ：sm2_sign
@IDE    ：PyCharm
@Author ：LiuXin
@Date   ：2020/8/3 23:01
@Desc   ：
=================================================="""

from PyQt5 import QtCore

from gmssl import sm2, func, sm3
from Util import TypeConvert


def str_add_space(out_str: str) -> str:
    """
    Add a space ever 2 char
    """
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str.strip()


def list_chr(list):
    str = ''
    for i in list:
        str += chr(i)
    return str


def str_hexlist(str):
    list = []
    for i in str:
        list.append(ord(i))
    return list


class SM2SignatureKeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str, str)

    def __init__(self, parent):
        super(SM2SignatureKeyThread, self).__init__(parent)
        private_key = '128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263'
        public_key = '0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857'
        self.sm2_crypt = sm2.CryptSM2(
            public_key=public_key, private_key=private_key)

    def run(self):
        d, P = self.sm2_crypt.generate_key()
        self.call_back.emit(str_add_space(d.upper()), str_add_space(P.upper()))


class SM2HashThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, ID, P, msg):
        super(SM2HashThread, self).__init__(parent)
        self.ID = ID
        self.P = P
        self.msg = msg

    def run(self):
        idAhex = str_hexlist(self.ID)
        a = sm2.default_ecc_table['a']
        b = sm2.default_ecc_table['b']
        len_g = len(sm2.default_ecc_table['g'])
        xG = sm2.default_ecc_table['g'][:int(len_g / 2)]
        yG = sm2.default_ecc_table['g'][int(len_g / 2):]
        xA = self.P[:int(len(self.P) / 2)]
        yA = self.P[int(len(self.P) / 2):]

        hexlist = []
        hexlist.append(0)
        hexlist.append(len(idAhex) * 8)
        hexlist.extend(idAhex)
        hexlist.extend(TypeConvert.str_to_hex_list(a))
        hexlist.extend(TypeConvert.str_to_hex_list(xG))
        hexlist.extend(TypeConvert.str_to_hex_list(yG))
        hexlist.extend(TypeConvert.str_to_hex_list(xA))
        hexlist.extend(TypeConvert.str_to_hex_list(yA))

        za = sm3.sm3_hash(hexlist)
        za = TypeConvert.str_to_hex_list(za)
        M = str_hexlist(self.msg)
        M_ = []
        M_.extend(za)
        M_.extend(M)

        e = sm3.sm3_hash(M_)

        self.call_back.emit(str_add_space(e.upper()))


class SM2SignatureThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str, str)

    def __init__(self, parent, d, P, e):
        super(SM2SignatureThread, self).__init__(parent)
        self.sm2_crypt = sm2.CryptSM2(
            public_key=P, private_key=d)
        self.k = None
        self.e = e

    def run(self):
        self.k = func.random_hex(self.sm2_crypt.para_len)
        sign = self.sm2_crypt.sign(self.e, self.k)
        self.call_back.emit(str_add_space(sign.upper()).strip(), str_add_space(self.k.upper()).strip())


class SM2VerificationThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, d, P, signature, e):
        super(SM2VerificationThread, self).__init__(parent)
        self.sm2_crypt = sm2.CryptSM2(
            public_key=P, private_key=d)
        self.signature = signature
        self.e = e

    def run(self):
        # try:
        verify = self.sm2_crypt.verify(self.signature, self.e)
        if verify:
            self.call_back.emit("Verify successes.")
        else:
            self.call_back.emit("Verify fails.")
    # except Exception as e:
    #     self.call_back.emit("Verify fails.")
    #     logging.error(e)
