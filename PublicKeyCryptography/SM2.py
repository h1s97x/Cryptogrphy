#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""=================================================
@Project -> File   ：sm2_encrypt
@IDE    ：PyCharm
@Author ：LiuXin
@Date   ：2020/8/3 23:01
@Desc   ：
=================================================="""
import logging
from PyQt5 import QtCore
from gmssl import sm2, func
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


def list_chr(chr_list):
    string = ''
    for i in chr_list:
        string += chr(i)
    return string


class SM2EncryptKeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str, str, str)

    def __init__(self, parent):
        super(SM2EncryptKeyThread, self).__init__(parent)
        private_key = ''
        public_key = ''
        self.sm2_crypt = sm2.CryptSM2(
            public_key=public_key, private_key=private_key)

    def run(self):
        d, P = self.sm2_crypt.generate_key()
        k = func.random_hex(self.sm2_crypt.para_len)
        self.call_back.emit(str_add_space(d.upper()), str_add_space(P.upper()), str_add_space(k.upper()))


class SM2EncryptThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, d, P, k, message):
        super(SM2EncryptThread, self).__init__(parent)
        self.sm2_crypt = sm2.CryptSM2(
            public_key=P.replace(" ", ""), private_key=d.replace(" ", ""))
        self.k = k.replace(" ", "")
        self.msg = message

    def run(self) -> None:
        self.encrypt_run()

    def encrypt_run(self) -> None:
        ciphertext = self.sm2_crypt.encrypt(self.msg.encode(), self.k)
        self.call_back.emit(str_add_space(ciphertext.upper()))


if __name__ == '__main__':
    P = '435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42'
    d = '1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0'
    msg = bytes(
        [0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72,
         0x64])
    k = '4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F'
    sm2_crypt = sm2.CryptSM2(public_key=P, private_key=d)
    ciphertext = sm2_crypt.encrypt(msg, k)
    pass


class SM2DecryptThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(str)

    def __init__(self, parent, d, P, ciphertext):
        super(SM2DecryptThread, self).__init__(parent)
        self.sm2_crypt = sm2.CryptSM2(public_key=P, private_key=d)
        self.ciphertext = ciphertext

    def run(self) -> None:
        self.decrypt_run()

    def decrypt_run(self) -> None:
        try:
            plaintext = self.sm2_crypt.decrypt(bytes(TypeConvert.str_to_hex_list(self.ciphertext)))
            plaintext = list_chr(list(plaintext))
            self.call_back.emit(plaintext)
        except Exception as e:
            logging.error(e)
