from PyQt5.QtWidgets import QApplication

from PublicKeyCryptography.ECC import ECC
from Modules import Button, PlainTextEdit, Group
from Modules import CryptographyWidget


class ECCWidget(CryptographyWidget):
    key = None
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.setWindowTitle("ECC Encryption")
        self.menuBar().setHidden(True)
        self.widgets_dict = {}
        self.key_a = None
        self.key_b = None
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[
                      PlainTextEdit(id="k", label="k",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="K", label="K",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="r", label="r",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Generate_key", name="Generate Key", clicked_function=self.generate_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.key_text_clean)
                  ]),

            Group(name="Encryption",
                  plain_text_edits=[
                      PlainTextEdit(id="Message", label="Message",
                                    default_text="encryption standard"),
                      PlainTextEdit(id="Ciphertext", label="Ciphertext",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_text_clean),
                  ]),

            Group(name="Decryption",
                  plain_text_edits=[
                      PlainTextEdit(id="ciphertext", label="Ciphertext",
                                    default_text=""),
                      PlainTextEdit(id="Plaintext", label="Message",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Decrypt", name="Decrypt", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_text_clean)
                  ]),
        ]

        self.render()
        self.logging.log("ECC algorithm has been imported.\n")

    def generate_key(self):
        try:
            thread = ECC.ECCKeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_key(self, k, K, r, key_a, key_b):
        self.logging.log("Generate key completes.")
        self.logging.log("k: {}".format(k))
        self.logging.log("K: {}".format(K))
        self.logging.log("r: {}\n".format(r))
        self.widgets_dict["k"].set_text(k)
        self.widgets_dict["K"].set_text(K)
        self.widgets_dict["r"].set_text(r)
        self.key_a = key_a
        self.key_b = key_b

    def key_text_clean(self):
        self.widgets_dict["k"].set_text("")
        self.widgets_dict["K"].set_text("")
        self.widgets_dict["r"].set_text("")
        self.key = None

    def computer_encrypt(self):
        try:
            k = self.widgets_dict["k"].get_text().strip()
            K = self.widgets_dict["K"].get_text().strip()
            r = self.widgets_dict["r"].get_text().strip()
            plaintext = self.widgets_dict["Message"].get_text().strip()
            if k != "" and K != "" and r != "" and plaintext != "":
                self.logging.log("ECC encryption begins.\n")
                thread = ECC.ECCEncryptThread(self, plaintext, self.key_a, self.key_b)
                thread.call_back.connect(self.set_up_ciphertext)
                thread.call_back.connect(self.widgets_dict["ciphertext"].set_text)
                thread.start()
                self.logging.log("k:         {}".format(k))
                self.logging.log("K:         {}".format(K))
                self.logging.log("r:         {}".format(r))
            else:
                self.logging.log("Please generate key first or input message.\n")
                self.pop_message_box("Please generate key first or input message.")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def encrypt_text_clean(self):
        self.widgets_dict["Ciphertext"].set_text("")

    def set_up_ciphertext(self, ciphertext):
        self.logging.log("ciphertext:{}".format(ciphertext) + "\n")
        self.widgets_dict["Ciphertext"].set_text(ciphertext)

    def computer_decrypt(self):
        try:
            k = self.widgets_dict["k"].get_text().strip()
            K = self.widgets_dict["K"].get_text().strip()
            ciphertext = self.widgets_dict["ciphertext"].get_text().strip()
            if k != "" and K != "" and ciphertext != "":
                self.logging.log("ECC decryption begins.\n")
                thread = ECC.ECCDecryptThread(self, ciphertext.replace(" ", ""), self.key_a, self.key_b)
                thread.call_back.connect(self.set_up_plaintext)
                thread.start()
                self.logging.log("k:         {}".format(k))
                self.logging.log("ciphertext:{}".format(ciphertext))
            else:
                self.logging.log("Please generate key first or input ciphertext.\n")
                self.pop_message_box("Please generate key first or input message.")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def decrypt_text_clean(self):
        self.widgets_dict["Plaintext"].set_text("")

    def set_up_plaintext(self, plaintext):
        if plaintext != "0":
            self.logging.log("plaintext: {}".format(plaintext) + "\n")
            self.widgets_dict["Plaintext"].set_text(plaintext)
        else:
            self.logging.log("Ciphertext Error. Please Re-enter.\n")
            self.pop_message_box("Ciphertext Error. Please Re-enter.")

if __name__ == '__main__':
    app = QApplication([])
    window = ECCWidget()
    app.exec_()
