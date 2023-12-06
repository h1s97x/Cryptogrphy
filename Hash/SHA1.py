import io
import logging
import struct
from PyQt5 import QtCore
from Util import TypeConvert


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


def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


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
        message_byte = bytearray(TypeConvert.int_to_hex_list(self.message, self.message_len))
        self.update(message_byte)
        result = self.hex_digest()
        return change_result_format(result)

    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64
    _h = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    # bytes object with 0 <= len < 64 used to store the end of the message
    # if the message length is not congruent to 64
    _unprocessed = b''
    # Length in bytes of all data that has been processed so far
    _message_byte_length = 0

    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hex-digest.
        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = self._process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hex_digest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _process_chunk(self, chunk, h0, h1, h2, h3, h4):
        """Process a chunk of data and return the new digest variables."""
        assert len(chunk) == 64

        w = [0] * 80

        # Break chunk into sixteen 4-byte big-endian words w[i]
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

        # Extend the sixteen 4-byte words into eighty 4-byte words
        for i in range(16, 80):
            w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, _left_rotate(b, 30), c, d)
            self.print_intermediate_value("%02d" % i + " " + format_w([a, b, c, d, e, f]).upper())

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

        return h0, h1, h2, h3, h4

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        self.print_intermediate_value('Fill ' + 'bit' + ':')
        w = preprocess_message(message)[0]

        self.print_intermediate_value(format_w(w).upper())
        self.print_intermediate_value('       A        B        C        D        E        F')
        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = self._process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return self._process_chunk(message[64:], *h)
