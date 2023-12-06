from collections import OrderedDict
from PyQt5 import QtCore


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, key, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.path = None
        self.key = key
        self.encrypt_selected = encrypt_selected
        self.plaintext_alphabet = []
        self.ciphertext_alphabet = []
        self.key = "".join(OrderedDict.fromkeys(self.key))
        for i in range(len(self.key)):
            self.ciphertext_alphabet.append(self.key[i])
        for i in range(26):
            self.plaintext_alphabet.append(chr(ord('a') + i))
            if not (self.plaintext_alphabet[i] in self.key):
                self.ciphertext_alphabet.append(self.plaintext_alphabet[i])
        # print(self.ciphertext_alphabet)

    # encrypt script
    def encrypt_run(self):
        result = self.encrypt()
        self.print_final_result(result)

    # decrypt script
    def decrypt_run(self):
        result = self.decrypt()
        self.print_final_result(result)

    # encrypt script
    def encrypt_txt_run(self):
        f = open(self.input_text, 'r', encoding='utf-8')
        text = f.read()
        f.close()
        self.path = self.input_text
        self.input_text = str(text)
        result = self.encrypt_txt()
        self.print_final_result(result)

    # decrypt script
    def decrypt_txt_run(self):
        f = open(self.input_text, 'r', encoding='utf-8')
        text = f.read()
        f.close()
        self.path = self.input_text
        self.input_text = str(text)
        result = self.decrypt_txt()
        self.print_final_result(result)

    def print_final_result(self, text):
        self.final_result.emit(text)

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.encrypt_run()
        elif self.encrypt_selected == 1:
            self.decrypt_run()
        elif self.encrypt_selected == 2:
            self.encrypt_txt_run()
        else:
            self.decrypt_txt_run()

    def encrypt(self):
        str_list = list(self.input_text)
        i = 0
        while i < len(self.input_text):
            if not self.judge_letter(str_list[i]):
                str_list[i] = str_list[i]
            else:
                if str_list[i].isupper():
                    b = self.ciphertext_alphabet[ord(str_list[i]) - ord('A')]
                    str_list[i] = chr(ord(b) - 32)
                else:
                    str_list[i] = self.ciphertext_alphabet[ord(str_list[i]) - ord('a')]
            i += 1
        result = "".join(str_list)
        return result

    def decrypt(self):
        str_list = list(self.input_text)
        i = 0
        while i < len(self.input_text):
            if not self.judge_letter(str_list[i]):
                str_list[i] = str_list[i]
            else:
                if str_list[i].isupper():
                    for j in range(0, 26):
                        if str_list[i] == chr(ord(self.ciphertext_alphabet[j]) - 32):
                            str_list[i] = chr(ord(self.plaintext_alphabet[j]) - 32)
                            break
                else:
                    for j in range(0, 26):
                        if str_list[i] == self.ciphertext_alphabet[j]:
                            str_list[i] = self.plaintext_alphabet[j]
                            break
            i += 1
        result = "".join(str_list)
        return result

    def encrypt_txt(self):
        ciphertext = self.encrypt()
        t = self.path.split('.')
        filename = str(t[0]) + '_MonoalphabeticEncryption.txt'
        fh = open(filename, 'w', encoding='utf-8')
        fh.write(ciphertext)
        fh.close()
        return filename

    def decrypt_txt(self):
        plaintext = self.decrypt()
        t = self.path.split('.')
        filename = str(t[0]) + '_MonoalphabeticDecryption.txt'
        fh = open(filename, 'w', encoding='utf-8')
        fh.write(plaintext)
        fh.close()
        return filename

    @staticmethod
    def judge_letter(s):
        if 97 <= ord(s) <= 122 or 65 <= ord(s) <= 90:
            return True
        else:
            return False
