import logging
from PyQt5 import QtCore
from Util import TypeConvert

# Initial permut matrix for the datas
PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Initial permut made on the key
CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Permut applied on shifted key to get Ki+1
CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# Expand matrix to get a 48bits matrix of datas to apply the xor with Ki
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S_BOX
S_BOX = [

    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
     ],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
     ],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
     ],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
     ],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
     ],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
     ],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
     ],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
     ]
]

# Permut made after each SBox substitution for each round
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Final permut for datas after the 16 rounds
PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

# Matrix that determine the shift for each round of keys
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def string_to_bit_array(text):  # Convert a string into a list of bits
    array = list()
    for char in text:
        bin_val = bin_value(char, 8)  # Get the char value on one byte
        array.extend([int(x) for x in list(bin_val)])  # Add the bits to the final list
    return array


def bit_array_to_string(array, length):
    res = ''
    for i in range(len(array)):
        if (i + 1) % length == 0:
            res += str(array[i]) + ' '
        else:
            res += str(array[i])
    res = res
    return res


def bit_array_to_hex_list(array):
    hex_list = []
    for y in [''.join([str(x) for x in _bytes]) for _bytes in n_split(array, 8)]:
        hex_list.append(int(y, 2))
    return hex_list


def bit_array_to_hex_string(array):
    res = ''.join(['{0:02x} '.format(int(y, 2), '0x').upper() for y in
                   [''.join([str(x) for x in _bytes]) for _bytes in n_split(array, 8)]])
    return res


def bin_value(val, bit_size):  # Return the binary value as a string of the given size
    bin_val = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(bin_val) > bit_size:
        raise "binary value larger than the expected size"
    while len(bin_val) < bit_size:
        bin_val = "0" + bin_val  # Add as many 0 as needed to get the wanted size
    return bin_val


def n_split(s, n):  # Split a list into sublist of size "n"
    return [s[k:k + n] for k in range(0, len(s), n)]


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, input_text_len, key, key_len, encrypt_selected, encryption_mode):
        super(Thread, self).__init__(parent)
        self.key_bits = None
        self.input_text = input_text
        self.input_text_len = input_text_len
        self.key = key
        self.key_len = key_len
        self.encrypt_selected = encrypt_selected
        self.encryption_mode = encryption_mode

    # encrypt script
    def encrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Encryption begins******************************/")
        self.print_intermediate_value("\nPlaintext:" + TypeConvert.int_to_str(self.input_text, self.input_text_len))
        self.print_intermediate_value("Key:" + TypeConvert.int_to_str(self.key, self.key_len))
        self.print_intermediate_value('Intermediate values')
        result = self.encrypt()
        self.print_intermediate_value("Encrypted:" + TypeConvert.int_to_str(result, 8))
        self.print_intermediate_value("Encryption completed\n\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, 8))

    # decrypt script
    def decrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Decryption begins******************************/")
        self.print_intermediate_value("\nCiphertext:" + TypeConvert.int_to_str(self.input_text, self.input_text_len))
        self.print_intermediate_value("Key:" + TypeConvert.int_to_str(self.key, self.key_len))
        result = self.decrypt()
        self.print_intermediate_value("Decrypted:" + TypeConvert.int_to_str(result, 8))
        self.print_intermediate_value("Decryption completed\n\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, 8))

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        else:
            self.decrypt_run()

    def encrypt(self):
        plaint_byte = TypeConvert.int_to_hex_list(self.input_text, self.input_text_len)
        key_byte = TypeConvert.int_to_hex_list(self.key, self.key_len)
        if self.encryption_mode == 0:
            result = self.des_main(plaint_byte, key_byte, 0)
        else:
            key1 = key_byte[0:8]
            key2 = key_byte[8:16]
            key3 = key_byte[16:24]
            result = self._3des_main(plaint_byte, key1, key2, key3, 0)
        return TypeConvert.hex_list_to_int(result)

    def decrypt(self):
        cipher_byte = TypeConvert.int_to_hex_list(self.input_text, self.input_text_len)
        key_byte = TypeConvert.int_to_hex_list(self.key, self.key_len)
        if self.encryption_mode == 0:
            result = self.des_main(cipher_byte, key_byte, 1)
        else:
            key3 = key_byte[0:8]
            key2 = key_byte[8:16]
            key1 = key_byte[16:24]
            result = self._3des_main(cipher_byte, key1, key2, key3, 1)
        return TypeConvert.hex_list_to_int(result)

    def des_main(self, input_text, key, action=0):
        keys = self.generate_keys(key)  # Generate all the keys
        text_blocks = n_split(input_text, 8)  # Split the int_data in blocks of 8 bytes to 64 bits
        result = list()
        for block in text_blocks:  # Loop over all the blocks of data
            block = string_to_bit_array(block)  # Convert the block in bit array
            self.print_intermediate_value('Input bits:' + bit_array_to_string(block, 8))
            self.print_intermediate_value('Key bits:' + bit_array_to_string(self.key_bits, 8))
            block = self.permut(block, PI)  # Apply the initial permutation
            g, d = n_split(block, 32)  # g(LEFT), d(RIGHT)
            self.print_intermediate_value('L[0] :' + bit_array_to_string(g, 8))
            self.print_intermediate_value('R[0] :' + bit_array_to_string(d, 8))
            for i in range(16):  # Do the 16 rounds
                self.print_intermediate_value('Round ' + str(i + 1))
                d_e = self.expand(d, E)  # Expand d to match Ki size (48bits)
                self.print_intermediate_value('E   : ' + bit_array_to_string(d_e, 6))
                if action == 0:
                    tmp = self.xor(keys[i], d_e)  # If encrypt use Ki
                    self.print_intermediate_value('KS  : ' + bit_array_to_string(keys[i], 6))
                    self.print_intermediate_value('E xor KS: ' + bit_array_to_string(tmp, 6))
                else:
                    tmp = self.xor(keys[15 - i], d_e)  # If decrypt start by the last key
                    self.print_intermediate_value('KS  : ' + bit_array_to_string(keys[i], 6))
                    self.print_intermediate_value('E xor KS: ' + bit_array_to_string(tmp, 6))

                tmp = self.substitute(tmp)  # Method that will apply the SBOXes
                self.print_intermediate_value('Sbox: ' + bit_array_to_string(tmp, 6))
                tmp = self.permut(tmp, P)
                self.print_intermediate_value('P   : ' + bit_array_to_string(tmp, 8))
                tmp = self.xor(g, tmp)
                g = d
                d = tmp
                self.print_intermediate_value('L[' + str(i + 1) + ']: ' + bit_array_to_string(g, 8))
                self.print_intermediate_value('R[' + str(i + 1) + ']: ' + bit_array_to_string(d, 8))

            result += self.permut(d + g, PI_1)  # Do the last permut and append the result to result
            self.print_intermediate_value('LR[16]: ' + bit_array_to_string(result, 8))

        final_res = bit_array_to_hex_list(result)
        return final_res  # Return the final string of data ciphered/deciphered

    def _3des_main(self, text, key1, key2, key3, action=0):
        self.print_intermediate_value('\n----------Starting first encryption----------')
        result1 = self.des_main(text, key1, action)
        self.print_intermediate_value('\n----------Starting second decryption----------')
        result2 = self.des_main(result1, key2, 1 - action)
        self.print_intermediate_value('\n----------Starting third encryption----------')
        result3 = self.des_main(result2, key3, action)
        return result3

    @staticmethod
    def substitute(d_e):  # Substitute bytes using S_BOX
        sub_blocks = n_split(d_e, 6)  # Split bit array into sublist of 6 bits
        result = list()
        for i in range(len(sub_blocks)):  # For all the sub_lists
            block = sub_blocks[i]
            row = int(str(block[0]) + str(block[5]), 2)  # Get the row with the first and last bit
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)  # Column is the 2,3,4,5th bits
            val = S_BOX[i][row][column]  # Take the value in the S_BOX appropriated for the round (i)
            bin_var = bin_value(val, 4)  # Convert the value to binary
            result += [int(x) for x in bin_var]  # And append it to the resulting list
        return result

    @staticmethod
    def permut(block, table):  # Permut the given block using the given table (so generic method)
        return [block[x - 1] for x in table]

    @staticmethod
    def expand(block, table):  # Do the exact same thing than permut but for more clarity has been renamed
        return [block[x - 1] for x in table]

    @staticmethod
    def xor(t1, t2):  # Apply a xor and return the resulting list
        return [x ^ y for x, y in zip(t1, t2)]

    def generate_keys(self, key):  # Algorithm that generates all the keys
        keys = []
        self.key_bits = string_to_bit_array(key)
        key = string_to_bit_array(key)
        key = self.permut(key, CP_1)  # Apply the initial permut on the key
        g, d = n_split(key, 28)  # Split it in to (g->LEFT),(d->RIGHT)
        for i in range(16):  # Apply the 16 rounds
            g, d = self.shift(g, d, SHIFT[i])  # Apply the shift associated with the round (not always 1)
            tmp = g + d  # Merge them
            keys.append(self.permut(tmp, CP_2))  # Apply the permut to get the Ki
        return keys

    @staticmethod
    def shift(g, d, n):  # Shift a list of the given value
        return g[n:] + g[:n], d[n:] + d[:n]
