from PyQt5 import QtCore


# 以转子Wheel_V，以下各装置大致原理与其相似
class WheelV:
    def __init__(self, ring_setting, start_position):
        # 转子的固定内部连线，例如ZK为一对连线，输入Z输出K，输入K输出Z
        self.right_to_left = {'A': 'V', 'B': 'Z', 'C': 'B', 'D': 'R', 'E': 'G', 'F': 'I', 'G': 'T', 'H': 'Y', 'I': 'U',
                              'J': 'P', 'K': 'S', 'L': 'D', 'M': 'N', 'N': 'H', 'O': 'L', 'P': 'X', 'Q': 'A', 'R': 'W',
                              'S': 'M', 'T': 'J', 'U': 'Q', 'V': 'O', 'W': 'F', 'X': 'E', 'Y': 'C', 'Z': 'K'}
        self.left_to_right = {'V': 'A', 'Z': 'B', 'B': 'C', 'R': 'D', 'G': 'E', 'I': 'F', 'T': 'G', 'Y': 'H', 'U': 'I',
                              'P': 'J', 'S': 'K', 'D': 'L', 'N': 'M', 'H': 'N', 'L': 'O', 'X': 'P', 'A': 'Q', 'W': 'R',
                              'M': 'S', 'J': 'T', 'Q': 'U', 'O': 'V', 'F': 'W', 'E': 'X', 'C': 'Y', 'K': 'Z'}
        self.index = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        # 如果目前的转子位置与输入的不符，就转一格
        while self.index[0] != ring_setting:
            self.index.append(self.index[0])
            self.index.pop(0)
        while self.index[0] != start_position:
            self.rotate()
        self.turnover = ['Z']

    def signal_in(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.right_to_left[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def signal_out(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.left_to_right[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def rotate(self):
        self.index.append(self.index[0])
        self.index.pop(0)
        self.state.append(self.state[0])
        self.state.pop(0)


# ABCDEFGHIJKLMNOPQRSTUVWXYZ
# JPGVOUMFYQBENHZRDKASXLICTW
class WheelVI:
    def __init__(self, ring_setting, start_position):
        self.right_to_left = {'A': 'J', 'B': 'P', 'C': 'G', 'D': 'V', 'E': 'O', 'F': 'U', 'G': 'M', 'H': 'F', 'I': 'Y',
                              'J': 'Q', 'K': 'B', 'L': 'E', 'M': 'N', 'N': 'H', 'O': 'Z', 'P': 'R', 'Q': 'D', 'R': 'K',
                              'S': 'A', 'T': 'S', 'U': 'X', 'V': 'L', 'W': 'I', 'X': 'C', 'Y': 'T', 'Z': 'W'}
        self.left_to_right = {'J': 'A', 'P': 'B', 'G': 'C', 'V': 'D', 'O': 'E', 'U': 'F', 'M': 'G', 'F': 'H', 'Y': 'I',
                              'Q': 'J', 'B': 'K', 'E': 'L', 'N': 'M', 'H': 'N', 'Z': 'O', 'R': 'P', 'D': 'Q', 'K': 'R',
                              'A': 'S', 'S': 'T', 'X': 'U', 'L': 'V', 'I': 'W', 'C': 'X', 'T': 'Y', 'W': 'Z'}
        self.index = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        while self.index[0] != ring_setting:
            self.index.append(self.index[0])
            self.index.pop(0)
        while self.index[0] != start_position:
            self.rotate()
        self.turnover = ['Z', 'M']

    def signal_in(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.right_to_left[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def signal_out(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.left_to_right[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def rotate(self):
        self.index.append(self.index[0])
        self.index.pop(0)
        self.state.append(self.state[0])
        self.state.pop(0)


# ABCDEFGHIJKLMNOPQRSTUVWXYZ
# FKQHTLXOCBJSPDZRAMEWNIUYGV
class WheelVIII:
    def __init__(self, ring_setting, start_position):
        self.right_to_left = {'A': 'F', 'B': 'K', 'C': 'Q', 'D': 'H', 'E': 'T', 'F': 'L', 'G': 'X', 'H': 'O', 'I': 'C',
                              'J': 'B', 'K': 'J', 'L': 'S', 'M': 'P', 'N': 'D', 'O': 'Z', 'P': 'R', 'Q': 'A', 'R': 'M',
                              'S': 'E', 'T': 'W', 'U': 'N', 'V': 'I', 'W': 'U', 'X': 'Y', 'Y': 'G', 'Z': 'V'}
        self.left_to_right = {'F': 'A', 'K': 'B', 'Q': 'C', 'H': 'D', 'T': 'E', 'L': 'F', 'X': 'G', 'O': 'H', 'C': 'I',
                              'B': 'J', 'J': 'K', 'S': 'L', 'P': 'M', 'D': 'N', 'Z': 'O', 'R': 'P', 'A': 'Q', 'M': 'R',
                              'E': 'S', 'W': 'T', 'N': 'U', 'I': 'V', 'U': 'W', 'Y': 'X', 'G': 'Y', 'V': 'Z'}
        self.index = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        while self.index[0] != ring_setting:
            self.index.append(self.index[0])
            self.index.pop(0)
        while self.index[0] != start_position:
            self.rotate()
        self.turnover = ['Z', 'M']

    def signal_in(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.right_to_left[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def signal_out(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.left_to_right[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def rotate(self):
        self.index.append(self.index[0])
        self.index.pop(0)
        self.state.append(self.state[0])
        self.state.pop(0)


# ABCDEFGHIJKLMNOPQRSTUVWXYZ
# LEYJVCNIXWPBQMDRTAKZGFUHOS
class WheelBeta:
    def __init__(self, ring_setting, start_position):
        self.right_to_left = {'A': 'L', 'B': 'E', 'C': 'Y', 'D': 'J', 'E': 'V', 'F': 'C', 'G': 'N', 'H': 'I', 'I': 'X',
                              'J': 'W', 'K': 'P', 'L': 'B', 'M': 'Q', 'N': 'M', 'O': 'D', 'P': 'R', 'Q': 'T', 'R': 'A',
                              'S': 'K', 'T': 'Z', 'U': 'G', 'V': 'F', 'W': 'U', 'X': 'H', 'Y': 'O', 'Z': 'S'}
        self.left_to_right = {'L': 'A', 'E': 'B', 'Y': 'C', 'J': 'D', 'V': 'E', 'C': 'F', 'N': 'G', 'I': 'H', 'X': 'I',
                              'W': 'J', 'P': 'K', 'B': 'L', 'Q': 'M', 'M': 'N', 'D': 'O', 'R': 'P', 'T': 'Q', 'A': 'R',
                              'K': 'S', 'Z': 'T', 'G': 'U', 'F': 'V', 'U': 'W', 'H': 'X', 'O': 'Y', 'S': 'Z'}
        self.index = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        while self.index[0] != ring_setting:
            self.index.append(self.index[0])
            self.index.pop(0)
        while self.index[0] != start_position:
            self.index.append(self.index[0])
            self.index.pop(0)
            self.state.append(self.state[0])
            self.state.pop(0)

    def signal_in(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.right_to_left[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def signal_out(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.left_to_right[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin


# ABCDEFGHIJKLMNOPQRSTUVWXYZ
# RDOBJNTKVEHMLFCWZAXGYIPSUQ
class WheelUKWC:
    def __init__(self, ):
        self.IO = {'A': 'R', 'B': 'D', 'C': 'O', 'D': 'B', 'E': 'J', 'F': 'N', 'G': 'T', 'H': 'K', 'I': 'V', 'J': 'E',
                   'K': 'H', 'L': 'M', 'M': 'L', 'N': 'F', 'O': 'C', 'P': 'W', 'Q': 'Z', 'R': 'A', 'S': 'X', 'T': 'G',
                   'U': 'Y', 'V': 'I', 'W': 'P', 'X': 'S', 'Y': 'U', 'Z': 'Q'}
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    def signal_in(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.IO[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin


class WheelETW:
    def __init__(self, ):
        self.right_to_left = {'A': 'A', 'B': 'B', 'C': 'C', 'D': 'D', 'E': 'E', 'F': 'F', 'G': 'G', 'H': 'H', 'I': 'I',
                              'J': 'J', 'K': 'K', 'L': 'L', 'M': 'M', 'N': 'N', 'O': 'O', 'P': 'P', 'Q': 'Q', 'R': 'R',
                              'S': 'S', 'T': 'T', 'U': 'U', 'V': 'V', 'W': 'W', 'X': 'X', 'Y': 'Y', 'Z': 'Z'}
        self.left_to_right = {'A': 'A', 'B': 'B', 'C': 'C', 'D': 'D', 'E': 'E', 'F': 'F', 'G': 'G', 'H': 'H', 'I': 'I',
                              'J': 'J', 'K': 'K', 'L': 'L', 'M': 'M', 'N': 'N', 'O': 'O', 'P': 'P', 'Q': 'Q', 'R': 'R',
                              'S': 'S', 'T': 'T', 'U': 'U', 'V': 'V', 'W': 'W', 'X': 'X', 'Y': 'Y', 'Z': 'Z'}
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    def signal_in(self, in_letter):
        out_letter = self.right_to_left[in_letter]
        out_pin = self.state.index(out_letter)
        return out_pin

    def signal_out(self, in_pin):
        in_letter = self.state[in_pin]
        out_letter = self.left_to_right[in_letter]
        return out_letter


class WheelStecker:
    def __init__(self, ):
        self.IO = {'A': 'A', 'B': 'B', 'C': 'C', 'D': 'D', 'E': 'E', 'F': 'F', 'G': 'G', 'H': 'H', 'I': 'I', 'J': 'J',
                   'K': 'K', 'L': 'L', 'M': 'M', 'N': 'N', 'O': 'O', 'P': 'P', 'Q': 'Q', 'R': 'R', 'S': 'S', 'T': 'T',
                   'U': 'U', 'V': 'V', 'W': 'W', 'X': 'X', 'Y': 'Y', 'Z': 'Z'}
        self.state = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                      'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    def switch(self, l1, l2):
        self.IO[l1] = l2
        self.IO[l2] = l1

    def signal_in(self, in_letter):
        out_letter = self.IO[in_letter]
        return out_letter

    def signal_out(self, in_letter):
        out_letter = self.IO[in_letter]
        return out_letter


class EnigmaM4:
    def __init__(self, ring_setting, start_position, plugs):
        self.ukw = WheelUKWC()
        self.wheel1 = WheelVIII(ring_setting[3], start_position[3])
        self.wheel2 = WheelVI(ring_setting[2], start_position[2])
        self.wheel3 = WheelV(ring_setting[1], start_position[1])
        self.wheel4 = WheelBeta(ring_setting[0], start_position[0])
        self.etw = WheelETW()
        self.steckern = WheelStecker()

        for p in plugs:
            self.steckern.switch(p[0], p[1])

    def encrypt(self, letter):
        # 转子的位置符合要求后，转子旋转一次
        if self.wheel2.turnover.count(self.wheel2.index[0]) > 0:
            self.wheel3.rotate()
            self.wheel2.rotate()
        elif self.wheel1.turnover.count(self.wheel1.index[0]) > 0:
            self.wheel2.rotate()
        self.wheel1.rotate()
        # 对输入的明文进行加密，按照次序输入插线板、转子、反射器等装置中
        letter = self.steckern.signal_in(letter)

        pin = self.etw.signal_in(letter)
        pin = self.wheel1.signal_in(pin)
        pin = self.wheel2.signal_in(pin)
        pin = self.wheel3.signal_in(pin)
        pin = self.wheel4.signal_in(pin)
        pin = self.ukw.signal_in(pin)
        pin = self.wheel4.signal_out(pin)
        pin = self.wheel3.signal_out(pin)
        pin = self.wheel2.signal_out(pin)
        pin = self.wheel1.signal_out(pin)
        letter = self.etw.signal_out(pin)

        cypher = self.steckern.signal_out(letter)
        return cypher

    def show_current_position(self):
        position = ''
        position += self.wheel4.index[0]
        position += self.wheel3.index[0]
        position += self.wheel2.index[0]
        position += self.wheel1.index[0]


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, ring_setting, start_position, plugs, input_text, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.ring_setting = ring_setting
        self.start_position = start_position
        self.plugs = plugs
        self.input_text = input_text
        self.encrypt_selected = encrypt_selected

    # encrypt script
    def encrypt_run(self):
        result = self.encrypt()
        self.print_final_result(result)

    # decrypt script
    def decrypt_run(self):
        result = self.decrypt()
        self.print_final_result(result)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        else:
            self.decrypt_run()

    def encrypt(self):
        # ring_setting = 'EPEL'
        # start_position = 'CDSZ'
        # plugs = ['AE', 'BF', 'CM', 'DQ', 'HU', 'JN', 'LX', 'PR', 'SZ', 'VW']
        enigma = EnigmaM4(ring_setting=self.ring_setting, start_position=self.start_position, plugs=self.plugs)
        cypher = ''
        for char in self.input_text:
            cypher += enigma.encrypt(char)
        return cypher

    def decrypt(self):
        # ring_setting = 'EPEL'
        # start_position = 'CDSZ'
        # plugs = ['AE', 'BF', 'CM', 'DQ', 'HU', 'JN', 'LX', 'PR', 'SZ', 'VW']
        enigma = EnigmaM4(ring_setting=self.ring_setting, start_position=self.start_position, plugs=self.plugs)
        cypher = ''
        for char in self.input_text:
            cypher += enigma.encrypt(char)
        return cypher
