from PyQt5 import QtCore


class Thread(QtCore.QThread):
    final_result = QtCore.pyqtSignal(str)
    logging_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, input_text, key, encrypt_selected):
        super(Thread, self).__init__(parent)
        self.input_text = input_text
        self.key = key
        self.encrypt_selected = encrypt_selected

    def decrypt_run(self):
        result = '/******************************Statistics of Letter Occurrence Times begins*****************************/\n\n'
        result = result + self.count_num(self.input_text, '', '', '', 0)
        result += 'Statistics of Letter Occurrence Times completed\n'
        self.final_result.emit(result)

    # encrypt script
    def decrypt_multi_run(self):
        result = '/******************************Decryption with Fixed Combination begins*****************************/\n\n'
        guess_order = ['e', 'r', 'h', 't', 'a', 'n', 'd', 'i', 'o', 's', 'g', 'l', 'f', 'm', 'w', 'p', 'c', 'u', 'y',
                       'v', 'j', 'b', 'k', 'q', 'x', 'z']
        # e
        cipher = [self.count_num(self.input_text, '', '', [], 1)]
        # r er
        cipher.append(self.count_num(self.input_text, cipher[0], '', cipher, 1))
        # h he
        cipher.append(self.count_num(self.input_text, '', cipher[0], cipher, 1))
        # t th
        cipher.append(self.count_num(self.input_text, '', cipher[2], cipher, 1))
        # a hat
        cipher.append(self.count_num(self.input_text, cipher[2], cipher[3], cipher, 1))
        # n ent
        cipher.append(self.count_num(self.input_text, cipher[0], cipher[3], cipher, 1))
        # d and
        cipher.append(self.count_num(self.input_text, cipher[4] + cipher[5], '', cipher, 1))
        # i inter
        cipher.append(self.count_num(self.input_text, '', cipher[5] + cipher[3] + cipher[0] + cipher[1], cipher, 1))
        # o tion
        cipher.append(self.count_num(self.input_text, cipher[3] + cipher[7], cipher[5], cipher, 1))
        # s tions
        cipher.append(self.count_num(self.input_text, cipher[3] + cipher[7] + cipher[8] + cipher[5], '', cipher, 1))
        # g ing
        cipher.append(self.count_num(self.input_text, cipher[7] + cipher[5], '', cipher, 1))
        # l girl
        cipher.append(self.count_num(self.input_text, cipher[10] + cipher[7] + cipher[1], '', cipher, 1))
        # f for
        cipher.append(self.count_num(self.input_text, '', cipher[8] + cipher[1], cipher, 1))
        # m ment
        cipher.append(self.count_num(self.input_text, '', cipher[0] + cipher[5] + cipher[3], cipher, 1))
        # w with
        cipher.append(self.count_num(self.input_text, '', cipher[7] + cipher[3] + cipher[2], cipher, 1))
        # p port
        cipher.append(self.count_num(self.input_text, '', cipher[8] + cipher[1] + cipher[3], cipher, 1))
        # c com
        cipher.append(self.count_num(self.input_text, '', cipher[8] + cipher[13], cipher, 1))
        # u put
        cipher.append(self.count_num(self.input_text, cipher[15], cipher[3], cipher, 1))
        # y you
        cipher.append(self.count_num(self.input_text, '', cipher[8] + cipher[17], cipher, 1))
        # v ever
        cipher.append(self.count_num(self.input_text, cipher[0], cipher[0] + cipher[1], cipher, 1))
        # j object
        cipher.append(self.count_num(self.input_text, '', cipher[0] + cipher[16] + cipher[3], cipher, 1))
        # b able
        cipher.append(self.count_num(self.input_text, cipher[4], cipher[11] + cipher[0], cipher, 1))
        # k speak
        cipher.append(self.count_num(self.input_text, cipher[9] + cipher[15] + cipher[0] + cipher[4], '', cipher, 1))
        # q quir
        cipher.append(self.count_num(self.input_text, '', cipher[17] + cipher[7] + cipher[1], cipher, 1))
        # x excuse
        cipher.append(self.count_num(self.input_text, cipher[0], cipher[16] + cipher[17], cipher, 1))
        # z
        cipher.append(self.count_num(self.input_text, '', '', cipher, 1))

        for i in range(0, 26):
            result = result + '密文' + str(cipher[i]) + '对应的明文为: ' + str(guess_order[i]) + '\n'

        result += 'Decryption with Fixed Combination completed\n'
        self.final_result.emit(result)

        f = open(self.input_text, 'r', encoding='utf-8')
        text = f.read()
        f.close()
        text = str(text)

        for i in range(0, 26):
            text = text.replace(cipher[i], '|~|' + str(cipher[i]))
            text = text.replace(chr(ord(cipher[i]) - 32), '|~|' + chr(ord(cipher[i]) - 32))
        for i in range(0, 26):
            text = text.replace('|~|' + cipher[i], guess_order[i])
            text = text.replace('|~|' + chr(ord(cipher[i]) - 32), chr(ord(guess_order[i]) - 32))

        t = self.input_text.split('.')
        filename = str(t[0]) + '_MultiDecryption.txt'
        fh = open(filename, 'w', encoding='utf-8')
        fh.write(text)
        fh.close()
        self.logging_result.emit("The storage path of the plaintext file is :  " + str(filename))

    # execute this function after start function executed
    def run(self):
        if self.encrypt_selected == 0:
            self.decrypt_run()
        else:
            self.decrypt_multi_run()

    @staticmethod
    def count_num(filepath, a, b, cipher_text, encrypt_selected):
        f = open(filepath, 'r', encoding='utf-8')
        text1 = f.read()
        f.close()
        text1 = str(text1)
        text1 = text1.replace('\\n', '')
        text2 = text1.casefold()
        word = []
        num = []
        single_word = []
        for i in range(0, 26):
            single_word.append(chr(ord('a') + i))
            word.append(str(a) + str(single_word[i]) + str(b))
        for i in range(0, 26):
            a = (len(text2) - len(text2.replace(str(word[i]), ''))) // len(str(word[i]))
            num.append(a)

        if encrypt_selected == 2:
            return num
        else:
            for i in range(0, 25):
                for j in range(i + 1, 26):
                    if num[i] < num[j]:
                        num[i], num[j] = num[j], num[i]
                        word[i], word[j] = word[j], word[i]
                        single_word[i], single_word[j] = single_word[j], single_word[i]

            if encrypt_selected == 0:
                str_ = ''
                for i in range(0, 26):
                    str_ = str_ + '密文' + str(word[i]) + '出现的次数是: ' + str(num[i]) + '\n'
                return str_
            else:
                _result = str(single_word[0])
                # _result = _result.replace(b, '').replace(a, '')
                i = 1
                while True:
                    if not (_result in cipher_text):
                        break
                    else:
                        _result = str(single_word[i])
                        # _result = _result.replace(b, '').replace(a, '')
                        i += 1
                return _result

    @staticmethod
    def judge_letter(s):
        if 97 <= ord(s) <= 122 or 65 <= ord(s) <= 90:
            return True
        else:
            return False
