from PyQt5 import QtCore


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)
    result = None

    def __init__(self, parent, input_text, key, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key = key
        self.encrypt_selected = encrypt_selected

    # encrypt script
    def encrypt_run(self):
        self.result = self.encrypt(self.input_text, self.key)
        self.print_final_result(self.result)

    # decrypt script
    def decrypt_run(self):
        self.result = self.decrypt(self.input_text, self.key)
        self.print_final_result(self.result)

    # encrypt script
    def encrypt_txt_run(self):
        self.result = self.encrypt_txt(self.input_text, self.key)
        self.print_final_result(self.result)

    # decrypt script
    def decrypt_txt_run(self):
        self.result = self.decrypt_txt(self.input_text, self.key)
        self.print_final_result(self.result)

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

    def encrypt(self, plaintext, key):
        str_list = list(plaintext)
        i = 0
        result = None
        while i < len(plaintext):
            if not self.judge_letter(str_list[i]):
                str_list[i] = str_list[i]
            else:
                a = "a"
                if str_list[i].isupper():
                    a = "A"
                str_list[i] = chr((ord(str_list[i]) - ord(a) + int(key)) % 26 + ord(a))
            i += 1
            result = "".join(str_list)
        return result

    def decrypt(self, ciphertext, key):
        str_list = list(ciphertext)
        i = 0
        result = None
        while i < len(ciphertext):
            if not self.judge_letter(str_list[i]):
                str_list[i] = str_list[i]
            else:
                a = "a"
                if str_list[i].isupper():
                    a = "A"
                str_list[i] = chr((ord(str_list[i]) - ord(a) - int(key)) % 26 + ord(a))
            i += 1
            result = "".join(str_list)
        return result

    def encrypt_txt(self, plaintext, key):
        f = open(plaintext, 'r', encoding='utf-8')
        text = f.read()
        f.close()
        text = str(text)
        ciphertext = self.encrypt(text, key)
        t = plaintext.split('.')
        filename = str(t[0]) + '_CaesarEncryption.txt'
        fh = open(filename, 'w', encoding='utf-8')
        fh.write(ciphertext)
        fh.close()
        return filename

    def decrypt_txt(self, ciphertext, key):
        f = open(ciphertext, 'r', encoding='utf-8')
        text = f.read()
        f.close()
        text = str(text)
        plaintext = self.decrypt(text, key)
        t = ciphertext.split('.')
        filename = str(t[0]) + '_CaesarDecryption.txt'
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
