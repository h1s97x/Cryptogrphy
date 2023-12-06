import decimal
import itertools
import logging
from PyQt5 import QtCore
from Util import TypeConvert


def hex_to_str(s):
    return ''.join([chr(i) for i in s])


def change_result_format(result):
    result_format = ''
    for i in range(len(result) // 2):
        result_format += result[i * 2:i * 2 + 2].upper() + ' '
    return result_format.strip()


def format_w(w):
    format = []
    for i in w:
        format.append('{0:08x} '.format(i, '0x'))
    return ''.join(format[i] for i in range(len(w)))


"""Generates prime numbers in order using the Sieve of Eratosthenes approach."""


def primes():
    d = {}
    q = 2
    while True:
        if q not in d:
            yield q
            d[q * q] = [q]
        else:
            for p in d[q]:
                d.setdefault(p + q, []).append(p)
            del d[q]
        q += 1


def sha_256_constant(p, r):
    """Generates the value of a constant used for SHA-256 as defined by FIPS
    180-4. A constant is the first 32 bits of the fractional part of the r-th
    root of a prime p, i.e. frac(p ^ (1 / r)) * 2^32."""
    return int(decimal.Decimal(p) ** (decimal.Decimal(1) / r) % 1 * 2 ** 32)


def rotate_right(x, n):
    """Right-rotates the bits in a 32-bit integer x by n bits. Defined in FIPS
    180-4 in section 3.2."""
    return (x >> n) | (x << 32 - n)


def choose(x, y, z):
    """The "Ch" function as defined in FIPS 180-4 equation (4.2). For each bit
    i in 32-bit words x, y, and z if x[i] is set then result[i] is y[i],
    otherwise result[i] is z[i]. In other words the bit in x determines if the
    result bit comes from y or z."""
    return (x & y) ^ (~x & z)


def majority(x, y, z):
    """The "Maj" function as defined in FIPS 180-4 equation (4.3). For each bit
    i in 32-bit words x, y, and z if the majority of x[i], y[i], and z[i] are
    set then result[i] is set, otherwise result[i] is not set."""
    return (x & y) ^ (x & z) ^ (y & z)


def sum_0(x):
    """The "Σ0" function as defined in FIPS 180-4 equation (4.4)."""
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)


def sum_1(x):
    """The "Σ1" function as defined in FIPS 180-4 equation (4.5)."""
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)


def rho_0(x):
    """The "σ0" function as defined in FIPS 180-4 equation (4.6)."""
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)


def rho_1(x):
    """The "σ1" function as defined in FIPS 180-4 equation (4.7)."""
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10)


def preprocess_message(m):
    """Preprocesses a message as defined in FIPS 180-4 section 5. Specifically,
    adds padding to a SHA-256 message as defined in FIPS 180-4 section 5.1.1,
    and splits the message into 512-bit blocks as defined in FIPS 180-4 section
    5.2.1."""
    length = len(m)
    m += b'\x80'  # Append 0b10000000.
    m += b'\x00' * (64 - (length + 9) % 64)  # Append sufficient padding.
    m += (length * 8).to_bytes(8, byteorder='big')  # Append 64-bit length.
    return [[int.from_bytes(m[b * 64 + w * 4: b * 64 + w * 4 + 4], 'big')
             for w in range(0, 16)] for b in range(0, len(m) // 64)]


# Initial hash values used by the SHA-256 algorithm. This is equivalent to the
# table defined in FIPS-180 section. 5.3.3. "... the first thirty-two bits of
# the frational parts of the square roots of the first eight prime numbers."
IV = [sha_256_constant(p, 2) for p in itertools.islice(primes(), 8)]

# Constants used by the SHA-256 algorithm. This is equivalent to the table
# defined in FIPS-180 section 4.2.2. "... the first thirty-two bits of the
# fractional parts of the cube roots of the first sixty-four prime numbers."
K = [sha_256_constant(p, 3) for p in itertools.islice(primes(), 64)]


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, message, message_len):
        super(Thread, self).__init__(parent)
        self.message = message
        self.message_len = message_len

    # hash script
    def hash_run(self):
        logging.info("thread running")
        self.print_intermediate_value("Hash begins")
        self.print_intermediate_value("Message:\n" + TypeConvert.int_to_str(self.message, self.message_len))
        result = self.hash()
        self.print_intermediate_value("Hash:\n" + result)
        self.print_intermediate_value("Hash completed\n\n")
        self.print_final_result(result)

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        self.hash_run()

    def hash(self):
        message_byte = TypeConvert.int_to_hex_list(self.message, self.message_len)
        result = self.sha256(hex_to_str(message_byte).encode('latin1')).hex()
        return change_result_format(result)

    def sha256(self, m):
        """Computes the SHA-256 hash of a given message. Defined by FIPS 108-4
        section 6.2.1."""
        H = IV.copy()
        cnt = 0

        for w in preprocess_message(m):
            self.print_intermediate_value('Fill ' + str(cnt) + ':')
            self.print_intermediate_value(format_w(w).upper())
            self.print_intermediate_value('       A        B        C        D        E        F        G        H')
            cnt += 1
            a, b, c, d, e, f, g, h = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
            for t in range(0, 64):
                if t >= 16:
                    w.append((rho_1(w[t - 2]) + w[t - 7] + rho_0(w[t - 15]) + w[t - 16]) % 2 ** 32)
                t1 = (h + sum_1(e) + choose(e, f, g) + K[t] + w[t]) % 2 ** 32
                t2 = (sum_0(a) + majority(a, b, c)) % 2 ** 32
                h = g
                g = f
                f = e
                e = (d + t1) % 2 ** 32
                d = c
                c = b
                b = a
                a = (t1 + t2) % 2 ** 32
                self.print_intermediate_value("%02d" % t + " " + format_w([a, b, c, d, e, f, g, h]).upper())
            H = [(v[0] + v[1]) % 2 ** 32 for v in zip([a, b, c, d, e, f, g, h], H)]
        return b''.join([h.to_bytes(4, 'big') for h in H])
