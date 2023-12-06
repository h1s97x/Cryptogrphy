from MathMagic.Modules.CryptographyModule import CryptographyWidget, Path, IntroductionTab, Group, PlainTextEdit, Button
from Crypto.PublicKey import ECC
import Menu.CryptographicAlgorithm.PublicKeyCryptography.ECDSA.ECDSA as ECDSA
from Util import TypeConvert, Path


def str_add_space(out_str: str) -> str:
    """
    Add a space ever 2 char
    """
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str


class REWidget(CryptographyWidget):
    key = None

    def __init__(self, parent):
        CryptographyWidget.__init__(self, parent)
        self.setWindowTitle("Replay Attack")
        self.tabs_config = [IntroductionTab(link="file:///" + Path.MENU_DIRECTORY +
                                                 "/CryptographicAlgorithm/CryptographicProtocol/Replay_Attack/html/index.html")]
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[
                      PlainTextEdit(id="Private_Key", label="Private Key(Str)", default_text="", read_only=True),
                      PlainTextEdit(id="Public_Key", label="PublicKey", default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Generate_Key", name="Generate Key", clicked_function=self.generate_key),
                      Button(id="Key_Clean", name="Clean", clicked_function=self.key_clean)
                  ]),
            Group(name="Alice",
                  plain_text_edits=[
                      PlainTextEdit(id="Message_Alice", label="Message(Str)", default_text="Message"),
                      PlainTextEdit(id="Signature_Alice", label="Signature", default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Sign", name="Sign", clicked_function=self.sign),
                      Button(id="Alice_Clean", name="Clean", clicked_function=self.alice_clean)
                  ]),
            Group(name="Assailant",  # 攻击者
                  plain_text_edits=[
                      PlainTextEdit(id="Message_Assailant", label="Alice_Message", default_text="", read_only=True),
                      PlainTextEdit(id="Signature_Assailant", label="Alice_Signature", default_text=""),
                  ],
                  buttons=[
                      Button(id="Attack", name="Attack", clicked_function=self.attack),
                      Button(id="Assailant_Clean", name="Clean", clicked_function=self.assailant_clean)
                  ]),
            Group(name="Bob",
                  plain_text_edits=[
                      PlainTextEdit(id="Result", label="Result", default_text="", read_only=True)
                  ],
                  buttons=[
                      Button(id="Alice_Verify", name="Alice_Verify", clicked_function=self.alice_verify),
                      Button(id="Alice_Verify", name="Assailant_Verify", clicked_function=self.assailant_verify),
                      Button(id="Bob_Clean", name="Clean", clicked_function=self.bob_clean)
                  ])
        ]
        self.render()
        self.logging("RSA signature algorithm has been imported.\n")
        self.key = None

    def generate_key(self):
        self.key = ECC.generate(curve='P-256')
        private_key = hex(self.key.d).replace("0x", "")
        public_key = hex(self.key.pointQ.x).replace("0x", "") + hex(self.key.pointQ.y).replace("0x", "")
        self.logging('Private Key:' + str_add_space(private_key).upper())
        self.logging('Public Key :' + str_add_space(public_key).upper() + '\n')
        self.widgets_dict["Private_Key"].set_text(str_add_space(private_key).upper())
        self.widgets_dict["Public_Key"].set_text(str_add_space(public_key).upper())

    def key_clean(self):
        self.widgets_dict["Private_Key"].set_text("")
        self.widgets_dict["Public_Key"].set_text("")

    def sign(self):
        try:
            message = self.widgets_dict["Message_Alice"].get_text().encode()
            if message is None:
                self.logging("Please input Message.\n")
                self.pop_message_box("Please input Message.")
                return
            thread = ECDSA.ECDSASignatureThread(self, message, self.key)
            thread.call_back.connect(self.set_sign)
            thread.start()

        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    def set_sign(self, string):
        self.widgets_dict["Signature_Alice"].set_text(string)
        self.logging("signature:" + string)
        self.logging('\n')

    def alice_clean(self):
        self.widgets_dict["Signature_Alice"].set_text("")

    def attack(self):
        message = self.widgets_dict["Message_Alice"].get_text()
        signature = self.widgets_dict["Signature_Alice"].get_text()
        if message is None:
            self.logging("Please input Message.\n")
            self.pop_message_box("Please input Message.")
            return
        if signature is None:
            self.logging("Please get signature first.\n")
            self.pop_message_box("Please get signature first.")
            return
        self.widgets_dict["Message_Assailant"].set_text(message)
        self.widgets_dict["Signature_Assailant"].set_text(signature)

    def assailant_clean(self):
        self.widgets_dict["Message_Assailant"].set_text("")
        self.widgets_dict["Signature_Alice"].set_text("")

    def alice_verify(self):
        try:
            message = self.widgets_dict["Message_Alice"].get_text().encode()
            signature = TypeConvert.str_to_int(self.widgets_dict["Signature_Alice"].get_text()). \
                to_bytes(64, byteorder='big', signed=False)
            if signature is None:
                self.logging("Please get SignValue first.\n")
                self.pop_message_box("Please get SignValue first.")
                return
            if message is None:
                self.logging("Please get SignValue first.\n")
                self.pop_message_box("Please get SignValue first.")
                return
            thread = ECDSA.VerifySignatureThread(self, message, signature, self.key)
            thread.call_back.connect(self.set_result)
            thread.start()
        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    def assailant_verify(self):
        try:
            message = self.widgets_dict["Message_Assailant"].get_text().encode()
            signature = TypeConvert.str_to_int(self.widgets_dict["Signature_Assailant"].get_text()).to_bytes(64, byteorder='big', signed=False)
            if signature is None:
                self.logging("Please get SignValue first.\n")
                self.pop_message_box("Please get SignValue first.")
                return
            thread = ECDSA.VerifySignatureThread(self, message, signature, self.key)
            thread.call_back.connect(self.set_result)
            thread.start()
        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    def set_result(self, text):
        self.widgets_dict["Result"].set_text(text)
        self.logging("Result:    " + text)
        self.logging('\n')

    def bob_clean(self):
        self.widgets_dict["Result"].set_text("")
