from . import Digital_Envelope
from MathMagic.Modules.CryptographyModule import CryptographyWidget, Button, PlainTextEdit, IntroductionTab, IntermediateValueTab, SmartCardTab, SmartCard, Group, ErrorType
from Util import Path, TypeConvert


class DEWidget(CryptographyWidget):
    key = None

    def __init__(self, parent):
        CryptographyWidget.__init__(self, parent)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Digital Envelope")
        # set tabs widget configurations
        # link: link to the html file
        self.tabs_config = [IntroductionTab(
            link="file:///" + Path.MENU_DIRECTORY + "/CryptographicAlgorithm/CryptographicProtocol/Digital_Envelope/html/index.html"),
            IntermediateValueTab(enabled=False), SmartCardTab()]
        # set smart card  widget configurations
        self.smart_card_config = SmartCard()
        # set groups configurations
        # set plain text edit component configurations
        # set button component configurations'
        # id: the identity of the component
        # clicked_function: execute the function after the button clicked

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
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Hex)",
                                                  default_text="11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00"),
                                    PlainTextEdit(id="Symmetrickey", label="Symmetric Key (Hex)",
                                                  default_text="01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"),
                                    PlainTextEdit(id="Message", label="Message (Hex)",
                                                  default_text="", read_only=True)
                                    ],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[
                      PlainTextEdit(id="_Message", label="Message (Hex)", default_text=""),
                      PlainTextEdit(id="_Plaintext", label="Plaintext (Hex)", default_text="", read_only=True),
                      PlainTextEdit(id="_Symmetrickey", label="Symmetric Key (Hex)", default_text="")],
                  buttons=[
                      Button(id="CardDecrypt", name="Decrypt (Card)", clicked_function=self.card_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]
        # render user interface based on above-mentioned configurations
        self.render()
        self.logging("Digital Envelope algorithm has been imported.\n")

    # generate key
    def generate_key(self):
        try:
            thread = Digital_Envelope.KeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging(e)

    def set_up_key(self, key):
        self.key = key
        private_key = key[1]
        self.logging("Generate key completes.")
        self.logging("p: {}".format(TypeConvert.int_to_str(private_key.p, 64)))
        self.logging("q: {}".format(TypeConvert.int_to_str(private_key.q, 64)))
        self.logging("N: {}".format(TypeConvert.int_to_str(private_key.n, 128)))
        self.logging("e: {}".format(TypeConvert.int_to_str(private_key.e, 4)))
        self.logging("d: {}\n".format(TypeConvert.int_to_str(private_key.d, 128)))
        self.widgets_dict["p"].set_text(TypeConvert.int_to_str(private_key.p, 64))
        self.widgets_dict["q"].set_text(TypeConvert.int_to_str(private_key.q, 64))
        self.widgets_dict["N"].set_text(TypeConvert.int_to_str(private_key.n, 128))
        self.widgets_dict["e"].set_text(TypeConvert.int_to_str(private_key.e, 4))
        self.widgets_dict["d"].set_text(TypeConvert.int_to_str(private_key.d, 128))

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging widget
            self.logging("Encrypt on your computer.")
            self.encrypt_clean()
            if not self.error_check_str_to_hex_list(self.widgets_dict["Plaintext"].get_text()):
                return
            plaintext_list = TypeConvert.str_to_hex_list(self.widgets_dict["Plaintext"].get_text())
            if plaintext_list is None:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + "You should check the \"Plaintext\" input box.")
                self.logging("\n")
                return
            temp = len(plaintext_list)
            if temp != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Plaintext\" input box.")
                self.logging("\n")
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Symmetrickey"].get_text()):
                return
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["Symmetrickey"].get_text())
            if key_list is None:
                self.pop_message_box(
                    ErrorType.NotMeetRequirementError.value + "You should check the \"Symmetric Key\" input box.")
                self.logging("\n")
                return
            temp = len(key_list)
            if temp != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Symmetric Key\" input box.")
                self.logging("\n")
                return

            # get text from target widget
            # then convert str to int
            plaintext = TypeConvert.str_to_int(self.widgets_dict["Plaintext"].get_text())
            self.widgets_dict["Plaintext"].set_text(TypeConvert.int_to_str(plaintext, 16))
            self.logging("Plaintext:  " + TypeConvert.int_to_str(plaintext, 16))
            symmetrickey = TypeConvert.str_to_int(self.widgets_dict["Symmetrickey"].get_text())
            self.widgets_dict["Symmetrickey"].set_text(TypeConvert.int_to_str(symmetrickey, 16))
            self.logging("Symmetrickey:" + TypeConvert.int_to_str(symmetrickey, 16))

            if self.key is None:
                self.logging("Please generate a public-private key pair first.\n")
                self.pop_message_box("Please generate a public-private key pair first.")
                return

            thread = Digital_Envelope.RsaThread(parent=self, plaintext=plaintext, symmetric_key=symmetrickey, key=self.key)  # input_bytes=plaintext_bytes,
            thread.call_back.connect(self.widgets_dict["Message"].set_text)
            thread.call_back.connect(self.print_result_to_logging)
            thread.call_back.connect(self.widgets_dict["_Message"].set_text)
            self.logging("Encrypt on your computer.")
            thread.start()
        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    def print_result_to_logging(self, str_data):
        self.logging("Result:     " + str(str_data))
        self.logging("\n")

    def get_pre_apdus(self):
        apdus = []
        # rsa_length_apdu = [0x00, 0x2E, 0x00, 0x00, 0x02, 0x04, 0x00]
        # apdus.append(rsa_length_apdu)
        E = self.widgets_dict["e"].get_text()
        E = TypeConvert.str_to_hex_list(E)
        N = self.widgets_dict["N"].get_text()
        N = TypeConvert.str_to_hex_list(N)
        D = self.widgets_dict["d"].get_text()
        D = TypeConvert.str_to_hex_list(D)
        EN_apdu = [0x00, 0x52, 0x00, 0x00, 0x84]
        EN_apdu.extend(E)
        EN_apdu.extend(N)

        apdus.append(EN_apdu)
        D_apdu = [0x00, 0x52, 0x00, 0x01, 0x80]
        D_apdu.extend(D)
        apdus.append(D_apdu)

        # cal_APDU=[0x00,0x30,0x00,0x02,0x00]
        # apdus.append(cal_APDU)
        return apdus

    # decrypt on smart card
    def card_decrypt(self):
        try:
            self.decrypt_clean()
            if self.key is None:
                self.logging("Please generate a public-private key pair first.\n")
                self.pop_message_box("Please generate a public-private key pair first.")
                return
            self.logging("Decrypt on the smart card.")
            apdus = self.get_pre_apdus()
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Message"].get_text()):
                return
            plaintext_list = TypeConvert.str_to_hex_list(self.widgets_dict["_Message"].get_text())
            if plaintext_list is None:
                return

            if len(plaintext_list) != 144:
                self.logging(
                    "The length of input text should be 144 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(
                        len(plaintext_list)) + " now.\n")
                self.pop_message_box(
                    "The length of input text should be 144 bytes. Two hexadecimal characters represent one byte. The length of input is " + str(
                        len(plaintext_list)) + " now.")
                return

            # format
            ciphertext = TypeConvert.str_to_int(self.widgets_dict["_Message"].get_text())
            self.widgets_dict["_Message"].set_text(TypeConvert.int_to_str(ciphertext, 144))

            plain_text = self.widgets_dict["_Message"].get_text()
            plaintext_list = TypeConvert.str_to_hex_list(plain_text)

            symmetrickey = []
            for j in range(0, 128):
                symmetrickey.append(plaintext_list[j])
            decrypt_apdu = [0x00, 0x52, 0x01, 0x00, 0x80]
            decrypt_apdu.extend(symmetrickey)
            apdus.append(decrypt_apdu)

            aes_text = []
            for i in range(128, 144):
                aes_text.append(plaintext_list[i])
            decrypt_apdu2 = [0x00, 0x52, 0x01, 0x01, 0x10]
            decrypt_apdu2.extend(aes_text)
            apdus.append(decrypt_apdu2)

            ask_for_result = [0x00, 0xC0, 0x00, 0x00, 0x20]
            receive_data = self.smart_card_config.send_and_receive(apdus, ask_for_result)
            print(receive_data)
            if receive_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            self.logging("Send To Smart Card (e+N):     " + TypeConvert.hex_list_to_str(apdus[0]))
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[0]))
            self.logging("Send To Smart Card (d):       " + TypeConvert.hex_list_to_str(apdus[1]))
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[1]))
            # self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdus[2]))
            # self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[2]))
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdus[2]))
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdus[3]))
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(ask_for_result))
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[3]))

            temp = receive_data[len(receive_data) - 1]
            temp = temp[0:len(temp) - 2]
            temp_big = TypeConvert.hex_list_to_str(temp)
            temp = TypeConvert.hex_list_to_str(TypeConvert.str_to_hex_list(temp_big))
            temp_plaintext = ''
            temp_symmetrickey = ''
            for i in range(0, 47):
                temp_plaintext += (temp[i])
            for i in range(48, 95):
                temp_symmetrickey += (temp[i])
            self.widgets_dict["_Symmetrickey"].set_text(str(temp_symmetrickey))
            self.widgets_dict["_Plaintext"].set_text(str(temp_plaintext))
            self.logging('\n')

        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    def encrypt_clean(self):
        self.widgets_dict["Message"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")
        self.widgets_dict["_Symmetrickey"].set_text("")

    def key_clean(self):
        self.widgets_dict["N"].set_text("")
        self.widgets_dict["e"].set_text("")
        self.widgets_dict["d"].set_text("")
        self.widgets_dict["p"].set_text("")
        self.widgets_dict["q"].set_text("")
        self.key = None

    def error_check_str_to_hex_list(self, text: str) -> bool:
        if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
            self.logging('Input data contains characters that do not meet the requirements.\n')
            self.pop_message_box("Input data contains characters that do not meet the requirements.")
            return False
        elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
            self.logging(
                'The length of the input data does not meet the requirements. Input length must be a multiple of 2.\n')
            self.pop_message_box(
                "The length of the input data does not meet the requirements. Input length must be a multiple of 2.")
            return False
        elif TypeConvert.str_to_hex_list(text) is None:
            return False
        else:
            return True
