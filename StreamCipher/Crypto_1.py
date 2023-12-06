import logging
from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)
    key_stream_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, input_text_len, key, key_len, input_val, input_len, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key_source = key
        self.input_text_len = input_text_len
        self.key_len = key_len
        self.input = input_val
        self.input_len = input_len
        self.encrypt_selected = encrypt_selected

    # encrypt script
    def encrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Encryption begins")
        self.print_intermediate_value("Plaintext: " + TypeConvert.int_to_str(self.input_text, self.input_text_len))
        self.print_intermediate_value("Key: " + TypeConvert.int_to_str(self.key_source, self.input_text_len))
        self.print_intermediate_value("Input: " + TypeConvert.int_to_str(self.input, self.input_text_len))
        result = self.encrypt()
        self.print_intermediate_value("Encrypted: " + TypeConvert.int_to_str(result, self.input_text_len))
        self.print_intermediate_value("Encryption completed\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, self.input_text_len))

    # decrypt script
    def decrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Decryption begins")
        self.print_intermediate_value("Ciphertext: " + TypeConvert.int_to_str(self.input_text, self.input_text_len))
        self.print_intermediate_value("Key: " + TypeConvert.int_to_str(self.key_source, self.input_text_len))
        self.print_intermediate_value("Input: " + TypeConvert.int_to_str(self.input, self.input_text_len))
        result = self.decrypt()
        self.print_intermediate_value("Decrypted: " + TypeConvert.int_to_str(result, self.input_text_len))
        self.print_intermediate_value("Decryption completed\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, self.input_text_len))

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    def print_keystream(self, text):
        self.key_stream_result.emit(text)

    @staticmethod
    def int_to_bit_str(a, size=None):
        """ Convert int number to binary string """
        if size is None:
            size = len(hex(a)[2:]) * 4
        return (bin(a)[2:]).zfill(size)

    @staticmethod
    def bit_str_to_int(a):
        """ Convert binary string to int """
        return int(a, 2)

    def bit_str_to_hex(self, a):
        """ Convert binary string to hex """
        return hex(self.bit_str_to_int(a))

    @staticmethod
    def bit_str_to_int_list(a):
        a = list(a)
        for i in range(len(a)):
            a[i] = int(a[i])
        return a

    @staticmethod
    def int_list_to_bit_str(a):
        b = ''
        for i in range(0, len(a)):
            b += str(a[i])
        return b

    @staticmethod
    def left_one(a):
        for i in range(0, 47):
            a[i] = a[i + 1]
        a[47] = 0
        return a

    # fa,fb,fc函数，是对线性反馈移位寄存器输出的比特进行运算
    @staticmethod
    def fa(a, b, c, d):
        """ Apply filter function A.
        f_a = ((a or b) xor (a and d)) xor (c and ((a xor b) or d)) """
        return ((a | b) ^ (a & d)) ^ (c & ((a ^ b) | d))

    @staticmethod
    def fb(a, b, c, d):
        """ Apply filter function B
        f_b = ((a and b) or c) xor (a xor b) and (c or d) """
        return ((a & b) | c) ^ (a ^ b) & (c | d)

    @staticmethod
    def fc(a, b, c, d, e):
        """ Apply filter function C
        f_c = (a or ((b or e) and (d xor e))) xor ((a xor
        (b and d)) and ((c xor d) and (a and e))) """
        return (a | ((b | e) & (d ^ e))) ^ ((a ^ (b & d)) & ((c ^ d) & (a & e)))

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        else:
            self.decrypt_run()

    def encrypt(self):
        plaint_byte = TypeConvert.int_to_hex_list(self.input_text, self.input_text_len)
        key_stream_byte = self.get_key_stream()
        result = self.xor_logic(plaint_byte, key_stream_byte)
        return TypeConvert.hex_list_to_int(result)

    def decrypt(self):
        cipher_byte = TypeConvert.int_to_hex_list(self.input_text, self.input_text_len)
        key_stream_byte = self.get_key_stream()
        result = self.xor_logic(cipher_byte, key_stream_byte)
        return TypeConvert.hex_list_to_int(result)

    # 线性反馈移位寄存器的具体运算过程
    def get_key_stream(self):
        self.print_intermediate_value(
            "/******************************Keystream begins to generate*****************************/")
        key_stream = []
        input_value = self.int_to_bit_str(self.input, 32)
        input_value = self.bit_str_to_int_list(input_value)
        lfsr = self.bit_str_to_int_list(self.int_to_bit_str(self.key_source, 48))
        self.print_intermediate_value("Original LFSR: " + self.int_list_to_bit_str(lfsr))
        # 新比特由之前的比特异或得到
        for i in range(0, 32):
            xor_result = lfsr[0] ^ lfsr[5] ^ lfsr[9] ^ lfsr[10] ^ lfsr[12] ^ lfsr[14] \
                        ^ lfsr[15] ^ lfsr[17] ^ lfsr[19] ^ lfsr[24] ^ lfsr[25] ^ lfsr[27] \
                        ^ lfsr[29] ^ lfsr[35] ^ lfsr[39] ^ lfsr[41] ^ lfsr[42] ^ lfsr[43]
            new_bit = input_value[i] ^ xor_result
            lfsr = self.left_one(lfsr)
            lfsr[47] = new_bit
            # 初始化结束后，线性反馈移位寄存器的特定比特被选出，然后经过两层滤波函数
            fb1 = self.fb(lfsr[9], lfsr[11], lfsr[13], lfsr[15])
            fa2 = self.fa(lfsr[17], lfsr[19], lfsr[21], lfsr[23])
            fa3 = self.fa(lfsr[25], lfsr[27], lfsr[29], lfsr[31])
            fb4 = self.fb(lfsr[33], lfsr[35], lfsr[37], lfsr[39])
            fa5 = self.fa(lfsr[41], lfsr[43], lfsr[45], lfsr[47])
            fc6 = self.fc(fb1, fa2, fa3, fb4, fa5)
            # 最后得到密钥流
            key_stream.append(fc6)
            self.print_intermediate_value("Round " + str(i + 1))
            self.print_intermediate_value("Feedback bit: " + str(new_bit))
            self.print_intermediate_value("LFSR: " + self.int_list_to_bit_str(lfsr) + "\n")
        byte_list1 = ''
        byte_list2 = ''
        byte_list3 = ''
        byte_list4 = ''
        for i in range(0, 32):
            if 0 <= i < 8:
                byte_list1 += str(key_stream[i])
            elif 8 <= i < 16:
                byte_list2 += str(key_stream[i])
            elif 16 <= i < 24:
                byte_list3 += str(key_stream[i])
            else:
                byte_list4 += str(key_stream[i])
        key_stream_byte_lists = [self.bit_str_to_int(byte_list1), self.bit_str_to_int(byte_list2), self.bit_str_to_int(byte_list3), self.bit_str_to_int(byte_list4)]
        self.print_intermediate_value(
            "/******************************Keystream was generated successfully*****************************/")

        return key_stream_byte_lists

    def xor_logic(self, text, key_stream):
        res = []
        for i in range(len(text)):
            val = text[i] ^ key_stream[i]
            # val = ("%02X" % (plaintext[i] ^ keys[i]))  # XOR and taking hex
            res.append(val)
        self.print_intermediate_value("Keystream: " + TypeConvert.hex_list_to_str(key_stream))
        self.print_keystream("Keystream:  " + TypeConvert.hex_list_to_str(key_stream))
        return res
