# Reusable UI widgets

# 古典密码 UI 组件
from .Caesar_ui import CaesarWidget
from .Vigenere_ui import VigenereWidget
from .Hill_ui import HillWidget
from .Playfair_ui import PlayfairWidget
from .Enigma_ui import EnigmaWidget
from .Monoalphabetic_Cipher_ui import MonoalphabeticWidget
from .Frequency_Analysis_ui import FAWidget

# 对称加密 UI 组件
from .AES_ui import AESWidget
from .DES_ui import DESWidget
from .SM4_ui import SM4Widget
from .SIMON_ui import SIMONWidget
from .SPECK_ui import SPECKWidget
from .Block_Mode_ui import BlockModeWidget
from .RC4_ui import RC4Widget
from .ZUC_ui import ZUCWidget
from .SEAL_ui import SEALWidget
from .Crypto_1_ui import Crypto1Widget

# 非对称加密 UI 组件
from .RSA_ui import RSAWidget
from .RSA_Sign_ui import RSASignWidget
from .ECC_ui import ECCWidget
from .ECDSA_ui import ECDSAWidget
from .ElGamal_ui import ElGamalWidget
from .SM2_ui import SM2Widget
from .SM2_Sign_ui import SM2SignWidget

# 哈希算法 UI 组件
from .MD5_ui import MD5Widget
from .SHA1_ui import SHA1Widget
from .SHA256_ui import SHA256Widget
from .SHA3_ui import SHA3Widget
from .SM3_ui import SM3Widget
from .HMAC_MD5_ui import HMACMD5Widget
from .AES_CBC_MAC_ui import AESCBCMACWidget
from .Hash_Reverse_ui import HashReverseWidget

# 数学基础 UI 组件
from .CRT_ui import CRTWidget
from .Euclidean_ui import EuclideanWidget
from .Euler_ui import EulerWidget

# 其他 UI 组件
from .Password_System_ui import PasswordSystemWidget

__all__ = [
    # 古典密码
    'CaesarWidget', 'VigenereWidget', 'HillWidget', 'PlayfairWidget',
    'EnigmaWidget', 'MonoalphabeticWidget', 'FAWidget',
    # 对称加密
    'AESWidget', 'DESWidget', 'SM4Widget', 'SIMONWidget', 'SPECKWidget',
    'BlockModeWidget', 'RC4Widget', 'ZUCWidget', 'SEALWidget', 'Crypto1Widget',
    # 非对称加密
    'RSAWidget', 'RSASignWidget', 'ECCWidget', 'ECDSAWidget', 'ElGamalWidget',
    'SM2Widget', 'SM2SignWidget',
    # 哈希算法
    'MD5Widget', 'SHA1Widget', 'SHA256Widget', 'SHA3Widget', 'SM3Widget',
    'HMACMD5Widget', 'AESCBCMACWidget', 'HashReverseWidget',
    # 数学基础
    'CRTWidget', 'EuclideanWidget', 'EulerWidget',
    # 其他
    'PasswordSystemWidget',
]
