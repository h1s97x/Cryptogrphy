from PyQt5.QtWidgets import QApplication

from PublicKeyCryptography import RSA_Sign
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert


class RSASignWidget(CryptographyWidget):
    key = None
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("RSA Signature")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[
                      PlainTextEdit(id="p", label="p",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="q", label="q",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="N", label="N",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="e", label="e",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="d", label="d",
                                    default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Generatekey", name="Generate Key (PC)", clicked_function=self.generate_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.key_clean)
                  ]),
            Group(name="Bob (PC)",
                  plain_text_edits=[
                      PlainTextEdit(id="Message", label="Message",
                                    default_text="61 62 63"),
                      PlainTextEdit(id="Digest", label="Digest",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="Signature", label="Signature",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Hash", name="Hash", clicked_function=self.hash),
                      Button(id="Btn_Signature", name="Sign", clicked_function=self.computer_signature),
                      Button(id="Clean", name="Clean", clicked_function=self.clean),
                  ]),

            Group(name="Alice (Card)",
                  plain_text_edits=[
                      PlainTextEdit(id="_Message", label="Message",
                                    default_text=""),
                      PlainTextEdit(id="_Signature", label="Signature",
                                    default_text=""),
                      PlainTextEdit(id="Result", label="Verify Result",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Btn_Verify", name="Verify", clicked_function=self.card_verify),
                      Button(id="Clean", name="Clean", clicked_function=self.clean_result)
                  ]),
        ]

        self.render()
        self.logging.log("RSA signature algorithm has been imported.\n")

    # generate key
    def generate_key(self):
        try:
            thread = RSA_Sign.KeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_key(self, key):
        self.key = key
        # pub_key = key[0]
        private_key = key[1]
        # self.logging.log(pub_key)
        # self.logging.log(private_key)
        self.logging.log("Generate key completes.")
        self.logging.log("p: {}".format(TypeConvert.int_to_str(private_key.p, 64)))
        self.logging.log("q: {}".format(TypeConvert.int_to_str(private_key.q, 64)))
        self.logging.log("N: {}".format(TypeConvert.int_to_str(private_key.n, 128)))
        self.logging.log("e: {}".format(TypeConvert.int_to_str(private_key.e, 4)))
        self.logging.log("d: {}\n".format(TypeConvert.int_to_str(private_key.d, 128)))
        self.widgets_dict["p"].set_text(TypeConvert.int_to_str(private_key.p, 64))
        self.widgets_dict["q"].set_text(TypeConvert.int_to_str(private_key.q, 64))
        self.widgets_dict["N"].set_text(TypeConvert.int_to_str(private_key.n, 128))
        self.widgets_dict["e"].set_text(TypeConvert.int_to_str(private_key.e, 4))
        self.widgets_dict["d"].set_text(TypeConvert.int_to_str(private_key.d, 128))

    def hash(self):
        try:
            self.logging.log("Hash on your computer.")

            if not self.error_check_str_to_hex_list((self.widgets_dict["Message"].get_text()), 'Message'):
                return
            message_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["Message"].get_text()))
            if message_len == 0:
                self.logging.log("The message length cannot be 0.\n")
                self.pop_message_box("The message length cannot be 0.")
                return
            elif message_len > 256:
                self.logging.log("The message length must bellow 256.\n")
                self.pop_message_box("The message length must bellow 256.\n")
                return

            # format input
            message = TypeConvert.str_to_int(self.widgets_dict["Message"].get_text())
            self.widgets_dict["Message"].set_text(TypeConvert.int_to_str(message, message_len))
            # get text from target widget
            # then convert str to int
            message = TypeConvert.str_to_int(self.widgets_dict["Message"].get_text())
            self.logging.log("Message: " + TypeConvert.int_to_str(message, message_len))
            thread = RSA_Sign.Sha256Thread(self, message, message_len)
            thread.final_result.connect(self.set_up_hash)
            thread.start()

        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_hash(self, hash_value):
        self.widgets_dict["Digest"].set_text(hash_value)
        self.logging.log('Hash:    ' + hash_value + '\n')

    # signature on computer
    def computer_signature(self):
        try:
            if self.key is None:
                self.logging.log("The Key cannot be empty. Please click the generate key button.\n")
                self.pop_message_box("The Key cannot be empty. Please click the generate key button.")
                return
            digest = self.widgets_dict["Digest"].get_text()
            if digest == '':
                self.logging.log("The digest cannot be empty. Please click the hash button.\n")
                self.pop_message_box("The digest cannot be empty. Please click the hash button.")
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Digest"].get_text(), 'Digest'):
                return
            digest_list = TypeConvert.str_to_hex_list(digest)
            # print(digest_list)

            digest_bytes = bytes(digest_list)
            thread = RSA_Sign.RsaSignThread(parent=self, input_bytes=digest_bytes, key=self.key)
            thread.call_back.connect(self.widgets_dict["Signature"].set_text)
            thread.call_back.connect(self.print_result_to_logging)
            thread.call_back.connect(self.widgets_dict["_Signature"].set_text)
            self.widgets_dict["_Message"].set_text(self.widgets_dict["Message"].get_text())
            # start RSA thread
            self.logging.log("Sign on your computer.\n")
            etext = TypeConvert.str_to_int(self.widgets_dict["e"].get_text())
            ntext = TypeConvert.str_to_int(self.widgets_dict["N"].get_text())
            # dtext= TypeConvert.str_to_int(self.widgets_dict["d"].get_text())
            self.logging.log("Hash:       " + TypeConvert.int_to_str(TypeConvert.str_to_int(digest), 32))
            self.logging.log("e:          " + TypeConvert.int_to_str(etext, 4))
            self.logging.log("N:          " + TypeConvert.int_to_str(ntext, 128))
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def print_result_to_logging(self, str_data):
        self.logging.log("Result:     " + str(str_data))
        self.logging.log("\n")

    # encrypt on smart card
    def card_verify(self):
        try:
            self.logging.log("Verify on the smart card.")
            if self.key is None:
                self.logging.log("Please generate a public-private key pair first.\n")
                self.pop_message_box("Please generate a public-private key pair first.")
                return
            message_len = len(TypeConvert.str_to_hex_list(self.widgets_dict["_Message"].get_text()))

            if message_len == 0:
                self.logging.log("The message length cannot be 0.\n")
                self.pop_message_box("The message length cannot be 0.")
                return
            elif message_len > 256:
                self.logging.log("The message length must bellow 256.\n")
                self.pop_message_box("The message length must bellow 256.\n")
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Message"].get_text(), 'Message'):
                return
                # format input
            message = TypeConvert.str_to_int(self.widgets_dict["_Message"].get_text())
            self.widgets_dict["_Message"].set_text(TypeConvert.int_to_str(message, message_len))
            # get text from target widget
            # then convert str to int
            message = TypeConvert.str_to_int(self.widgets_dict["_Message"].get_text())
            self.logging.log("Message: " + TypeConvert.int_to_str(message, message_len))
            message = TypeConvert.str_to_hex_list(self.widgets_dict["_Message"].get_text())

            if TypeConvert.str_to_hex_list(self.widgets_dict["_Message"].get_text()) is None:
                return

            apdus = self.get_pre_apdus()
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Signature"].get_text(), 'Signature'):
                return
            plaintext_list = TypeConvert.str_to_hex_list(self.widgets_dict["_Signature"].get_text())
            if plaintext_list is None:
                return

            if len(plaintext_list) != 128:
                self.logging.log(
                    "The length of input text should be 128 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(
                        len(plaintext_list)) + " now.\n")
                self.pop_message_box(
                    "The length of input text should be 128 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(
                        len(plaintext_list)) + " now.")
                return

            # format
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["_Signature"].get_text())
            self.widgets_dict["_Signature"].set_text(TypeConvert.int_to_str(ciphertext, 128))

            plain_text = self.widgets_dict["_Signature"].get_text()
            plaintext_list = TypeConvert.str_to_hex_list(plain_text)

            # 导入message
            message_apdu = [0x00, 0x30, 0x00, 0x02, message_len]
            message_apdu.extend(message)
            apdus.append(message_apdu)

            encrypt_apdu = [0x00, 0x30, 0x02, 0x00, 0x80]
            encrypt_apdu.extend(plaintext_list)
            apdus.append(encrypt_apdu)
            ask_for_result = [0x00, 0xC0, 0x00, 0x00, 0x80]
            receive_data = self.smart_card_config.send_and_receive(apdus, ask_for_result)
            if receive_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging.log("\n")
                return

            self.logging.log("Send To Smart Card (e+N):     " + TypeConvert.hex_list_to_str(apdus[0]))
            self.logging.log("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[0]))
            self.logging.log("Send To Smart Card (d):       " + TypeConvert.hex_list_to_str(apdus[1]))
            self.logging.log("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[1]))
            self.logging.log("Send To Smart Card (message): " + TypeConvert.hex_list_to_str(apdus[2]))
            self.logging.log("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[2]))
            self.logging.log("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdus[3]))
            # self.logging.log("Send To Smart Card:           " + TypeConvert.hex_list_to_str(ask_for_result))
            self.logging.log("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[3]))

            temp = receive_data[len(receive_data) - 1]
            if temp[0] == 0x90 and temp[1] == 0x00:
                self.widgets_dict["Result"].set_text('Certification success.')
            elif temp[0] == 0x68 and temp[1] == 0x00:
                self.widgets_dict["Result"].set_text('Certification fail.')
            else:
                return

        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def verify(self, pc_hash):
        pc_hash_list = TypeConvert.str_to_hex_list(pc_hash)
        card_result_list = TypeConvert.str_to_hex_list(self.card_result)
        bool_value = True

        for i in range(len(pc_hash_list)):
            if pc_hash_list[i] != card_result_list[i]:
                bool_value = False
                break

        if bool_value:
            self.widgets_dict["Result"].set_text('Certification success.')
        else:
            self.widgets_dict["Result"].set_text('Certification fail.')
        self.logging.log('\n')

    def get_pre_apdus(self):
        apdus = []
        # rsa_length_apdu = [0x00, 0x2E, 0x00, 0x00, 0x02, 0x04, 0x00]
        # apdus.append(rsa_length_apdu)
        E = TypeConvert.str_to_hex_list(self.widgets_dict["e"].get_text())
        N = TypeConvert.str_to_hex_list(self.widgets_dict["N"].get_text())
        D = TypeConvert.str_to_hex_list(self.widgets_dict["d"].get_text())
        EN_apdu = [0x00, 0x30, 0x00, 0x00, 0x84]
        EN_apdu.extend(E)
        EN_apdu.extend(N)

        apdus.append(EN_apdu)
        D_apdu = [0x00, 0x30, 0x00, 0x01, 0x80]
        D_apdu.extend(D)

        apdus.append(D_apdu)

        # cal_APDU = [0x00, 0x30, 0x00, 0x02, 0x00]
        # apdus.append(cal_APDU)
        return apdus

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

    def key_clean(self):
        self.widgets_dict["N"].set_text("")
        self.widgets_dict["e"].set_text("")
        self.widgets_dict["d"].set_text("")
        self.widgets_dict["p"].set_text("")
        self.widgets_dict["q"].set_text("")
        self.key = None

    def clean(self):
        self.widgets_dict["Message"].set_text("")
        self.widgets_dict["Digest"].set_text("")
        self.widgets_dict["Signature"].set_text("")

    def clean_result(self):
        self.widgets_dict["Result"].set_text("")

    def error_check_str_to_hex_list(self, text: str, input_name: str) -> bool:
        if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
            self.logging.log(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            self.pop_message_box(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            return False
        elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
            self.logging.log(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.\n')
            self.pop_message_box(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.')
            return False
        elif TypeConvert.str_to_hex_list(text) is None:
            return False
        else:
            return True

if __name__ == '__main__':
    app = QApplication([])
    window = RSASignWidget()
    app.exec_()
