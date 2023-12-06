from .SM2_Encryption import Encryption, Decryption, bytes_to_bits
from .SM2_Signature import Signature, Verification
from . import Prepare
from . import SM2_Code
from . import SM2_keyExchange


def Enc_Interface(M, PB):
    # tmpbit=bytes(M)
    # strl='1221'
    # bytes(strl)
    M = Prepare.M_to_bits(M)
    C = Encryption(M, PB)
    C = Prepare.bits_to_M(C)
    return C


def Dec_Interface(C, dB):
    C = SM2_Code.str_to_bytes(C)
    C = bytes_to_bits(C)
    C = C[2:len(C)]
    M_ = Decryption(C, dB)
    return Prepare.bits_to_M(M_)


### test Enc_Interface() and Dec_Interface() ###
'''
config.default_config()
parameters = config.get_parameters()
key = key_pair_generation(parameters)
dB = key[0]
PB = key[1]
M = ['a', 's']
print('M ', M)
C = Enc_Interface(M, PB)
print('C ', C)
print('M_', Dec_Interface(C, dB))
'''

'''
def Sig_Interface(M, IDA, dA, PA):
	M = M_to_bits(M)
	Sig = Signature(M, IDA, dA, PA)
	Sig = bytes_to_bits(Sig)
	Sig = bits_to_M(Sig)
	return Sig

def Ver_Interface(M, Sig, IDA, PA):
	Sig = str_to_bytes(Sig)
	print(Sig)
	M = M_to_bits(M)
	if Verification(M, Sig, IDA, PA) == False:
		return False
	return True
'''


def Sig_Interface(M, IDA, dA, PA):
    M = Prepare.M_to_bits(M)
    Sig = Signature(M, IDA, dA, PA)
    num = ''
    for i in Sig:
        i = "%03d" % i
        num = num + i
    Sig = str(hex(int(num)))
    Sig = Sig[2:len(Sig)]
    # Sig = bytes_to_bits(Sig)
    # Sig = bits_to_M(Sig)
    return Sig


def Ver_Interface(M, Sig, IDA, PA):
    Sig = int(Sig, 16)
    Sig = "%0192d" % Sig
    temp = str(Sig)
    Sig = []
    for i in range(0, 64):
        Sig.append(int(temp[i * 3:(i + 1) * 3]))
    M = Prepare.M_to_bits(M)
    if not Verification(M, Sig, IDA, PA):
        return False
    return True


### test Sig_Interface() and Ver_Interface() ###
'''
config.default_config()
parameters = config.get_parameters()
key = key_pair_generation(parameters)
dA = key[0]
PA = key[1]
IDA = 'ALICE123@YAHOO.COM'
M = ['a']
print('M ', M)
Sig = Sig_Interface(M, IDA, dA, PA)
print('Sig ', Sig)
Ver_Interface(M, Sig, IDA, PA)
'''


def keyEX_Interface_get_ZA_ZB(IDA, IDB, PA, PB):
    return SM2_keyExchange.get_ZA_ZB(IDA, IDB, PA, PB)


def keyEX_Interface_1():
    return SM2_keyExchange.key_generation_1()


def keyEX_Interface_2(ZA, ZB, r_self, R_self, R_opposite, d_self, P_self, P_opposite, klen, is_send):
    return SM2_keyExchange.key_generation_2(ZA, ZB, r_self, R_self, R_opposite, d_self, P_self, P_opposite, klen, is_send)


def keyEX_Interface_3(S_target, S_test):
    return SM2_keyExchange.key_generation_3(S_target, S_test)


### test keyExchange ###
'''
config.default_config()
parameters = config.get_parameters()
key = key_pair_generation(parameters)
dA = key[0]
PA = key[1]
key = key_pair_generation(parameters)
dB = key[0]
PB = key[1]
klen = 128

IDA = 'ALICE123@YAHOO.COM'
IDB = 'BILL456@YAHOO.COM'
RA, rA = keyEX_Interface_1()
RB, rB = keyEX_Interface_1()
ZA, ZB = keyEX_Interface_get_ZA_ZB(IDA, IDB, PA, PB)
kB, SB, S2 = key_generation_2(ZA, ZB, rB, RB, RA, dB, PB, PA, klen, 0)
print('kB', kB)
print('---------------------------------------------------------')
kA, SA, S1 = key_generation_2(ZA, ZB, rA, RA, RB, dA, PA, PB, klen, 1)
print('kA', kA)
#key_generation_B_1(IDA, IDB, RA, dB, PA, klen)
#key_generation_A_2(IDA, IDB, rA, RA, RB, SB, dA, PB, klen)
keyEX_Interface_3(SB, S1)
keyEX_Interface_3(SA, S2)
'''
