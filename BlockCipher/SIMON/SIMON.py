import logging
from collections import deque
from PyQt5 import QtCore
from Util import TypeConvert


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)
    # Z Arrays (stored bits reversed for easier usage)
    z0 = 0b01100111000011010100100010111110110011100001101010010001011111
    z1 = 0b01011010000110010011111011100010101101000011001001111101110001
    z2 = 0b11001101101001111110001000010100011001001011000000111011110101
    z3 = 0b11110000101100111001010001001000000111101001100011010111011011
    z4 = 0b11110111001001010011000011101000000100011011010110011110001011

    # valid cipher configurations stored:
    # block_size:{key_size:(number_rounds,z sequence)}
    __valid_setups = {32: {64: (32, z0)},
                      48: {72: (36, z0), 96: (36, z1)},
                      64: {96: (42, z2), 128: (44, z3)},
                      96: {96: (52, z2), 144: (54, z3)},
                      128: {128: (68, z2), 192: (69, z3), 256: (72, z4)}}
    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

    def __init__(self, parent, input_text, key, encrypt_selected, key_size=96, block_size=64, encryption_mode='ECB',
                 init=0, counter=0):
        """
        Initialize an instance of the html block cipher.
        param key: Int representation of the encryption key
        :param key_size: Int representing the encryption key in bits
        :param block_size: Int representing the block size in bits
        :param init: IV for CTR, CBC, PCBC, CFB, and OFB modes
        :param counter: Initial Counter value for CTR mode
        :return: None
        """
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key = key
        self.encrypt_selected = encrypt_selected
        self.encryption_mode = encryption_mode

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:', [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds, Z Sequence, and Key Size
        try:
            self.rounds, self.z_seq = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:', [x for x in self.possible_setups.keys()])
            raise
        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Parse the given iv and truncate it to the block length
        try:
            self.iv = init & ((2 ** self.block_size) - 1)
            self.iv_upper = self.iv >> self.word_size
            self.iv_lower = self.iv & self.mod_mask
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = counter & ((2 ** self.block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(encryption_mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        m = self.key_size // self.word_size
        self.key_schedule = []

        # Create list of sub-words from encryption key
        k_init = [((self.key >> (self.word_size * ((m - 1) - x))) & self.mod_mask) for x in range(m)]
        k_reg = deque(k_init)  # Use queue to manage key sub-words
        round_constant = self.mod_mask ^ 3  # Round Constant is 0xFFFF...FC

        # Generate all round keys
        for x in range(self.rounds):
            rs_3 = ((k_reg[0] << (self.word_size - 3)) + (k_reg[0] >> 3)) & self.mod_mask
            if m == 4:
                rs_3 = rs_3 ^ k_reg[2]
            rs_1 = ((rs_3 << (self.word_size - 1)) + (rs_3 >> 1)) & self.mod_mask
            c_z = ((self.z_seq >> (x % 62)) & 1) ^ round_constant
            new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]
            self.key_schedule.append(k_reg.pop())
            k_reg.appendleft(new_k)

    # encrypt script
    def encrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Encryption begins******************************/")
        self.print_intermediate_value("\nPlaintext:" + TypeConvert.int_to_str(self.input_text, self.block_size // 8))
        self.print_intermediate_value("Key:" + TypeConvert.int_to_str(self.key, self.key_size // 8))
        self.print_intermediate_value('Intermediate values')
        result = self.encrypt(self.input_text)
        self.print_intermediate_value("Encrypted:" + TypeConvert.int_to_str(result, self.block_size // 8))
        self.print_intermediate_value("Encryption completed\n\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, self.block_size // 8))

    # decrypt script
    def decrypt_run(self):
        logging.info("thread running")
        self.print_intermediate_value("/******************************Decryption begins******************************/")
        self.print_intermediate_value("\nCiphertext:" + TypeConvert.int_to_str(self.input_text, self.block_size // 8))
        self.print_intermediate_value("Key:" + TypeConvert.int_to_str(self.key, self.key_size // 8))
        result = self.decrypt(self.input_text)
        self.print_intermediate_value("Decrypted:" + TypeConvert.int_to_str(result, self.block_size // 8))
        self.print_intermediate_value("Decryption completed\n\n\n")
        self.print_final_result(TypeConvert.int_to_str(result, self.block_size // 8))

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

    def encrypt(self, plaintext):
        """
        Process new plaintext into ciphertext based on current cipher object setup
        :param plaintext: Int representing value to encrypt
        :return: Int representing encrypted value
        """
        try:
            b = (plaintext >> self.word_size) & self.mod_mask
            a = plaintext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext as int')
            raise

        if self.mode == 'ECB':
            b, a = self.encrypt_function(b, a)

        elif self.mode == 'CTR':
            true_counter = self.iv + self.counter
            d = (true_counter >> self.word_size) & self.mod_mask
            c = true_counter & self.mod_mask
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c
            self.counter += 1

        elif self.mode == 'CBC':
            b ^= self.iv_upper
            a ^= self.iv_lower
            b, a = self.encrypt_function(b, a)
            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a

        elif self.mode == 'PCBC':
            f, e = b, a
            b ^= self.iv_upper
            a ^= self.iv_lower
            b, a = self.encrypt_function(b, a)
            self.iv_upper = b ^ f
            self.iv_lower = a ^ e
            self.iv = (self.iv_upper << self.word_size) + self.iv_lower

        elif self.mode == 'CFB':
            d = self.iv_upper
            c = self.iv_lower
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c
            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a

        elif self.mode == 'OFB':
            d = self.iv_upper
            c = self.iv_lower
            d, c = self.encrypt_function(d, c)
            self.iv_upper = d
            self.iv_lower = c
            self.iv = (d << self.word_size) + c

            b ^= d
            a ^= c

        ciphertext = (b << self.word_size) + a
        return ciphertext

    def decrypt(self, ciphertext):
        """
        Process new ciphertext into plaintext based on current cipher object setup
        :param ciphertext: Int representing value to encrypt
        :return: Int representing decrypted value
        """
        try:
            b = (ciphertext >> self.word_size) & self.mod_mask
            a = ciphertext & self.mod_mask
        except TypeError:
            print('Invalid ciphertext!')
            print('Please provide ciphertext as int')
            raise

        if self.mode == 'ECB':
            a, b = self.decrypt_function(a, b)

        elif self.mode == 'CTR':
            true_counter = self.iv + self.counter
            d = (true_counter >> self.word_size) & self.mod_mask
            c = true_counter & self.mod_mask
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c
            self.counter += 1

        elif self.mode == 'CBC':
            f, e = b, a
            a, b = self.decrypt_function(a, b)
            b ^= self.iv_upper
            a ^= self.iv_lower
            self.iv_upper = f
            self.iv_lower = e
            self.iv = (f << self.word_size) + e

        elif self.mode == 'PCBC':
            f, e = b, a
            a, b = self.decrypt_function(a, b)
            b ^= self.iv_upper
            a ^= self.iv_lower
            self.iv_upper = (b ^ f)
            self.iv_lower = (a ^ e)
            self.iv = (self.iv_upper << self.word_size) + self.iv_lower

        elif self.mode == 'CFB':
            d = self.iv_upper
            c = self.iv_lower
            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c

        elif self.mode == 'OFB':
            d = self.iv_upper
            c = self.iv_lower
            d, c = self.encrypt_function(d, c)
            self.iv_upper = d
            self.iv_lower = c
            self.iv = (d << self.word_size) + c
            b ^= d
            a ^= c

        plaintext = (b << self.word_size) + a
        return plaintext

    def encrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of html Fiestel function to encrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper bytes of plaintext input
                    limited by word size of currently configured cipher
        lower_word: int of lower bytes of plaintext input
                    limited by word size of currently configured cipher
        x,y:        int of Upper and Lower ciphertext words
        """
        x = upper_word
        y = lower_word
        # print("upper:", hex(x))
        # print("lower", hex(y))
        i = 0
        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
            # Generate all circular shifts
            ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2

            i += 1
            self.print_intermediate_value("Round " + str(i) + ":")
            self.print_intermediate_value(TypeConvert.int_to_str((x << self.word_size) + y, self.block_size // 8))
        return x, y

    def decrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of html Fiestel function to decrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper bytes of ciphertext input
                    limited by word size of currently configured cipher
        lower_word: int of lower bytes of ciphertext input
                    limited by word size of currently configured cipher
        x,y:        int of Upper and Lower plaintext words
        """
        x = upper_word
        y = lower_word
        i = 0
        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule):
            # Generate all circular shifts
            ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2
            i += 1
            self.print_intermediate_value("Round " + str(i) + ":")
            self.print_intermediate_value(TypeConvert.int_to_str((x << self.word_size) + y, self.block_size // 8))
        return x, y

    def update_iv(self, new_iv):
        if new_iv:
            try:
                self.iv = new_iv & ((2 ** self.block_size) - 1)
                self.iv_upper = self.iv >> self.word_size
                self.iv_lower = self.iv & self.mod_mask
            except TypeError:
                print('Invalid Initialization Vector!')
                print('Please provide IV as int')
                raise
        return self.iv