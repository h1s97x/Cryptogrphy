from cryptography import x509
from cryptography.exceptions import InvalidSignature
from . import Digital_Certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert, Path


class DCWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.CA_key = None
        self.Card_key = None
        self.cert_path = Path.MENU_DIRECTORY + 'certificate.cer'
        # set window title
        self.setWindowTitle("Digital Certificate")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="CA RSA Key",
                  plain_text_edits=[
                      PlainTextEdit(id="CA_p", label="p",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="CA_q", label="q",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="CA_N", label="N",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="CA_e", label="e",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="CA_d", label="d",
                                    default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Generate_key", name="Generate Key (PC)", clicked_function=self.generate_key),
                      Button(id="CA_Key_Clean", name="Clean", clicked_function=self.ca_key_clean)
                  ]),
            Group(name="Get Card Public Key and Certificate",
                  plain_text_edits=[
                      PlainTextEdit(id="Card_e", label="e",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="Card_n", label="n",
                                    default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Get_Card_Key", name="Get Card Public Key", clicked_function=self.get_card_public_key),
                      Button(id="Certificate", name="Certificate", clicked_function=self.certificate),
                      Button(id="Card_Key_Clean", name="Clean", clicked_function=self.card_key_clean)
                  ]),
            Group(name="Verify",
                  plain_text_edits=[PlainTextEdit(id="Bin", label="Certificate Bin (Hex)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="Card_Signature", label="Card Signature (Hex)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="Verify_Text", label="Verify",
                                                  default_text="", read_only=True)
                                    ],

                  buttons=[
                      Button(id="Certificate_Hash", name="Certificate Hash", clicked_function=self.cert_bin),
                      Button(id="Get_Hash_From_Card", name="Get Hash From Card", clicked_function=self.get_hash_from_card),
                      Button(id="Verify", name="Verify", clicked_function=self.verify)
                  ])
        ]

        # render user interface based on above-mentioned configurations
        self.render()
        self.logging("Digital Certificate has been imported.\n")

    # generate key
    def generate_key(self):
        try:
            thread = Digital_Certificate.KeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging(e)

    def set_up_key(self, key):
        self.CA_key = key
        private_key = key[1]
        self.logging("Generate key completes.")
        self.logging("p: {}".format(TypeConvert.int_to_str(private_key.p, 64)))
        self.logging("q: {}".format(TypeConvert.int_to_str(private_key.q, 64)))
        self.logging("N: {}".format(TypeConvert.int_to_str(private_key.n, 128)))
        self.logging("e: {}".format(TypeConvert.int_to_str(private_key.e, 4)))
        self.logging("d: {}\n".format(TypeConvert.int_to_str(private_key.d, 128)))
        self.widgets_dict["CA_p"].set_text(TypeConvert.int_to_str(private_key.p, 64))
        self.widgets_dict["CA_q"].set_text(TypeConvert.int_to_str(private_key.q, 64))
        self.widgets_dict["CA_N"].set_text(TypeConvert.int_to_str(private_key.n, 128))
        self.widgets_dict["CA_e"].set_text(TypeConvert.int_to_str(private_key.e, 4))
        self.widgets_dict["CA_d"].set_text(TypeConvert.int_to_str(private_key.d, 128))

    def ca_key_clean(self):
        self.widgets_dict["CA_N"].set_text("")
        self.widgets_dict["CA_e"].set_text("")
        self.widgets_dict["CA_d"].set_text("")
        self.widgets_dict["CA_p"].set_text("")
        self.widgets_dict["CA_q"].set_text("")
        self.CA_key = None

    def get_card_public_key(self):
        generate_key = [0x00, 0x53, 0x00, 0x00, 0x00]
        ask_for_result = [0x00, 0xC0, 0x00, 0x01, 0x84]
        receive_data = self.widgets_dict["SmartCard"].send([generate_key, ask_for_result])
        if receive_data is None:
            self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader. ")
            self.logging("\n")
            return
        self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(generate_key))
        self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[0]))
        self.logging("Send To Smart Card :          " + TypeConvert.hex_list_to_str(ask_for_result))
        self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[1]))
        self.logging('\n')
        self.widgets_dict["Card_e"].set_text(TypeConvert.hex_list_to_str(receive_data[1][:4]))
        self.widgets_dict["Card_n"].set_text(TypeConvert.hex_list_to_str(receive_data[1][4:-2]))

    def certificate(self):
        try:
            if self.CA_key is None:
                self.logging("Please generate a public-private key pair first.\n")
                self.pop_message_box("Please generate a public-private key pair first.")
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Card_e"].get_text(), 'e'):
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["Card_n"].get_text(), 'n'):
                return
            card_e = TypeConvert.str_to_int(self.widgets_dict["Card_e"].get_text())
            card_n = TypeConvert.str_to_int(self.widgets_dict["Card_n"].get_text())
            self.widgets_dict["Card_e"].set_text(TypeConvert.int_to_str(card_e, 4))
            self.widgets_dict["Card_n"].set_text(TypeConvert.int_to_str(card_n, 128))
            self.logging("e: " + TypeConvert.int_to_str(card_e, 4))
            self.logging("n: " + TypeConvert.int_to_str(card_n, 128))
            thread = Digital_Certificate.CAThread(self, self.CA_key, (card_e, card_n))
            thread.result.connect(self.send_hash_to_card)
            thread.start()
            pass
        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    def send_hash_to_card(self, signature):
        set_sign = [0x00, 0x53, 0x00, 0x01, 0x80]
        set_sign.extend(list(signature))
        receive_data = self.widgets_dict["SmartCard"].send([set_sign])
        if receive_data is None:
            self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader. ")
            self.logging("\n")
            return
        self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(set_sign))
        self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[0]))
        self.logging('\n')

    def card_key_clean(self):
        self.widgets_dict["Card_e"].set_text("")
        self.widgets_dict["Card_n"].set_text("")

    def error_check_str_to_hex_list(self, text: str, input_name: str) -> bool:
        if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
            self.logging(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            self.pop_message_box(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
            return False
        elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
            self.logging(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.\n')
            self.pop_message_box(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.')
            return False
        elif TypeConvert.str_to_hex_list(text) is None:
            return False
        else:
            return True

    def cert_bin(self):
        try:
            with open(self.cert_path, 'rb') as file:
                cert = x509.load_der_x509_certificate(file.read())
            cert_list = list(cert.tbs_certificate_bytes)
            self.widgets_dict["Bin"].set_text(TypeConvert.hex_list_to_str(cert_list))
        except FileNotFoundError as e:
            self.pop_message_box('No such certificate file! Please Verify after Generate file!')

    def get_hash_from_card(self):
        ask_result = [0x00, 0xC0, 0x00, 0x04, 0x80]
        receive_data = self.widgets_dict["SmartCard"].send([ask_result])
        if receive_data is None:
            self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader. ")
            self.logging("\n")
            return
        self.logging("Send To Smart Card :          " + TypeConvert.hex_list_to_str(ask_result))
        self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(receive_data[0]))
        self.logging('\n')
        self.widgets_dict["Card_Signature"].set_text(TypeConvert.hex_list_to_str(receive_data[0][:-2]))

    def verify(self):
        if self.CA_key is None:
            self.logging("Please generate a public-private key pair first.\n")
            self.pop_message_box("Please generate a public-private key pair first.\n")
            return
        if self.widgets_dict["Card_Signature"].get_text() == '':
            self.logging("Please get signature from card first.\n")
            self.pop_message_box("Please get signature from card first.\n")
            return
        public_key = rsa.RSAPublicNumbers(self.CA_key[1].e, self.CA_key[1].n)
        cert_bin = TypeConvert.str_to_hex_list(self.widgets_dict["Bin"].get_text())
        signature = TypeConvert.str_to_hex_list(self.widgets_dict["Card_Signature"].get_text())
        try:
            public_key.public_key().verify(bytes(signature), bytes(cert_bin), padding.PKCS1v15(), hashes.SHA256())
            self.widgets_dict["Verify_Text"].set_text('Verify succeed.')
        except InvalidSignature:
            self.widgets_dict["Verify_Text"].set_text('Verify failed.')

    def compare(self, decrypt_result):
        pass
