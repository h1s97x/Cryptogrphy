from PyQt5.QtWidgets import QApplication, QVBoxLayout, QLabel, QPushButton, QWidget, QComboBox

from PublicKeyCryptography import SM2_Sign
from Util.Modules import Button, PlainTextEdit, Key, KeyGroup, Group, ErrorType, TextEdit, ComboBox
from Util.Modules import CryptographyWidget
from Util import Path, TypeConvert


class SM2SignWidget(CryptographyWidget):
    key = None
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("SM2 Signature")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                  plain_text_edits=[
                      PlainTextEdit(id="d", label="d (Hex)",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="P", label="P (Hex)",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Generatekey", name="Generate Key (PC)", clicked_function=self.generate_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.key_clean)
                  ]),

            Group(name="Hash",
                  plain_text_edits=[
                      PlainTextEdit(id="ID", label="ID",
                                    default_text="ALICE123@YAHOO.COM"),
                      PlainTextEdit(id="Message", label="Message",
                                    default_text="message digest"),
                      PlainTextEdit(id="e", label="e (Hex)",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Hash", name="Hash", clicked_function=self.hash),
                      Button(id="CleanHash", name="Clean", clicked_function=self.hash_clean),
                  ]),

            Group(name="Signature",
                  plain_text_edits=[
                      PlainTextEdit(id="_e", label="e (Hex)",
                                    default_text=""),
                      PlainTextEdit(id="k", label="k (Hex)",
                                    default_text="", read_only=True),
                      PlainTextEdit(id="Signature", label="Signature",
                                    default_text="", read_only=True),
                  ],
                  buttons=[
                      Button(id="Sign", name="Sign", clicked_function=self.signature),
                      Button(id="CleanSign", name="Clean", clicked_function=self.sign_clean),
                  ]),

            Group(name="Verification",
                  plain_text_edits=[
                      PlainTextEdit(id="_Signature", label="Signature",
                                    default_text=""),
                      PlainTextEdit(id="__e", label="e",
                                    default_text=""),
                      PlainTextEdit(id="_Verify", label="Verify",
                                    default_text=""),
                  ],
                  buttons=[
                      Button(id="Verify", name="Verify", clicked_function=self.verify),
                      Button(id="CleanVerify", name="Clean", clicked_function=self.verify_clean)
                  ]),
        ]
        self.render()
        self.logging.log("SM2 signature algorithm has been imported.\n")
        self.d = None
        self.P = None

    # generate key
    def generate_key(self):
        try:
            thread = SM2_Sign.SM2SignatureKeyThread(self)
            thread.call_back.connect(self.set_up_key)
            thread.start()
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_up_key(self, d, P):
        self.d = d
        self.P = P
        self.logging.log("Generate key completes.")
        self.logging.log("d: {}".format(d))
        self.logging.log("P: {}".format(P) + "\n")
        self.widgets_dict["d"].set_text(d.strip())
        self.widgets_dict["P"].set_text(P.strip())

    def key_clean(self):
        self.widgets_dict["d"].set_text("")
        self.widgets_dict["P"].set_text("")
        self.key = None

    # clean widget text
    def hash_clean(self):
        # self.widgets_dict["ID"].set_text("")
        # self.widgets_dict["Message"].set_text("")
        self.widgets_dict["e"].set_text("")

    # clean widget text
    def sign_clean(self):
        self.widgets_dict["_e"].set_text("")
        self.widgets_dict["Signature"].set_text("")

    # clean widget text
    def verify_clean(self):
        self.widgets_dict["_Signature"].set_text("")
        self.widgets_dict["_Verify"].set_text("")

    def hash(self):
        try:
            ID = self.widgets_dict["ID"].get_text().strip()
            msg = self.widgets_dict["Message"].get_text().strip()
            P = self.widgets_dict["P"].get_text().strip()
            if ID != '' and msg != '' and P != '':
                thread = SM2_Sign.SM2HashThread(self, ID, P.replace(" ", ""), msg)
                thread.call_back.connect(self.set_hash)
                thread.call_back.connect(self.widgets_dict["_e"].set_text)
                thread.call_back.connect(self.widgets_dict["__e"].set_text)
                thread.start()
            else:
                self.pop_message_box("Please generate key first or input Plaintext and ID.")
                self.logging.log("Please generate key first or input Plaintext and ID.\n")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_hash(self, e):
        self.logging.log("SM2 calculates e completes.")
        self.logging.log("e:{}".format(e) + "\n")
        self.widgets_dict["e"].set_text(e)

    def signature(self):
        try:
            d = self.widgets_dict["d"].get_text().strip()
            P = self.widgets_dict["P"].get_text().strip()
            if not self.error_check_str_to_hex_list(self.widgets_dict["_e"].get_text()):
                return
            e = self.widgets_dict["_e"].get_text().strip()
            if d != "" and P != "" and e != "":
                if len(e.replace(" ", "")) != 64:
                    self.logging.log("Length of e is wrong.\n")
                else:
                    self.logging.log("SM2 signature begins.")
                    self.logging.log("d:        {}".format(d))
                    self.logging.log("P:        {}".format(P))
                    self.logging.log("e:        {}".format(e))
                    thread = SM2_Sign.SM2SignatureThread(self, d.replace(" ", ""), P.replace(" ", ""), e.replace(" ", ""))
                    thread.call_back.connect(self.set_signature)
                    thread.call_back.connect(self.widgets_dict["_Signature"].set_text)
                    thread.start()
            else:
                self.pop_message_box("Please generate key first or input e.")
                self.logging.log("Please generate key first or input e.\n")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    def set_signature(self, signature, k):
        self.logging.log("k:        {}".format(k))
        self.logging.log("Signature:{}".format(signature) + "\n")
        self.widgets_dict["Signature"].set_text(signature)
        self.widgets_dict["k"].set_text(k)

    def verify(self):
        try:
            d = self.widgets_dict["d"].get_text().strip()
            P = self.widgets_dict["P"].get_text().strip()
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Signature"].get_text()):
                return
            signature = self.widgets_dict["_Signature"].get_text().strip()
            if not self.error_check_str_to_hex_list(self.widgets_dict["__e"].get_text()):
                return
            e = self.widgets_dict["__e"].get_text().strip()
            if d != "" and P != "" and signature != "" and e != "":
                if len(signature.replace(" ", "")) != 128 or len(e.replace(" ", "")) != 64:
                    self.logging.log("Length of signature or e is wrong.\n")
                else:
                    self.logging.log("SM2 verification begins.")
                    P_apdu = [0x00, 0x33, 0x00, 0x00, 0x40]
                    P_apdu.extend(TypeConvert.str_to_hex_list(P))
                    self.logging.log("Send To Smart Card (P):        " + TypeConvert.hex_list_to_str(P_apdu))
                    P_receive = self.widgets_dict["SmartCard"].send_apdus([P_apdu])
                    if P_receive is None:
                        self.pop_message_box(
                            ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                        self.logging.log("\n")
                        return
                    self.logging.log("Get Response From Smart Card:  " + TypeConvert.hex_list_to_str(P_receive[0]))

                    d_apdu = [0x00, 0x33, 0x00, 0x01, 0x20]
                    d_apdu.extend(TypeConvert.str_to_hex_list(d))
                    self.logging.log("Send To Smart Card (d):        " + TypeConvert.hex_list_to_str(d_apdu))
                    d_receive = self.widgets_dict["SmartCard"].send_apdus([d_apdu])
                    if d_receive is None:
                        self.pop_message_box(
                            ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                        self.logging.log("\n")
                        return
                    self.logging.log("Get Response From Smart Card:  " + TypeConvert.hex_list_to_str(d_receive[0]))

                    verify_apdu = [0x00, 0x33, 0x05, 0x01, 0x60]
                    verify_apdu.extend(TypeConvert.str_to_hex_list(e))
                    verify_apdu.extend(TypeConvert.str_to_hex_list(signature))
                    self.logging.log("Send To Smart Card (verify):   " + TypeConvert.hex_list_to_str(verify_apdu))
                    verify_receive = self.widgets_dict["SmartCard"].send_apdus([verify_apdu])
                    if verify_receive is None:
                        self.pop_message_box(
                            ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                        self.logging.log("\n")
                        return
                    self.logging.log(
                        "Get Response From Smart Card:  " + TypeConvert.hex_list_to_str(verify_receive[0]) + "\n")

                    if verify_receive[0][0] == 144:  # 90 00
                        self.set_verify("Verify successes.")
                    else:
                        self.set_verify("Verify fails.")

            else:
                self.pop_message_box("Please generate key first or input signature and e.")
                self.logging.log("Please generate key first or input signature and e.\n")
        except Exception as e:
            self.logging.log('Error:' + str(e) + '\n')

    # 封存代码（PC端verify）
    # def verify(self):
    #     try:
    #         d = self.widgets_dict["d"].get_text().strip()
    #         P = self.widgets_dict["P"].get_text().strip()
    #         signature = self.widgets_dict["_Signature"].get_text().strip()
    #         e = self.widgets_dict["__e"].get_text().strip()
    #         if d != "" and P != "" and signature != "" and e != "":
    #             if len(signature.replace(" ", "")) != 128 or len(e.replace(" ", "")) != 64:
    #                 self.logging.log("Length of signature or e is wrong.\n")
    #             else:
    #                 self.logging.log("SM2 verification begins.")
    #                 thread = lib.SM2VerificationThread(self, d.replace(" ", ""), P.replace(" ", ""), signature.replace(" ", ""), e.replace(" ", ""))
    #                 thread.call_back.connect(self.set_verify)
    #                 thread.start()
    #         else:
    #             self.logging.log("Please generate key first or input signature.\n")
    #     except Exception as e:
    #         self.logging.log('Error:' + str(e) + '\n')

    def set_verify(self, verification):
        self.widgets_dict["_Verify"].set_text(verification)

    def error_check_str_to_hex_list(self, text: str) -> bool:
        if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
            self.logging.log('Input data contains characters that do not meet the requirements.\n')
            self.pop_message_box("Input data contains characters that do not meet the requirements.")
            return False
        elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
            self.logging.log(
                'The length of the input data does not meet the requirements. Input length must be a multiple of 2.\n')
            self.pop_message_box(
                "The length of the input data does not meet the requirements. Input length must be a multiple of 2.")
            return False
        elif TypeConvert.str_to_hex_list(text) is None:
            return False
        else:
            return True

if __name__ == '__main__':
    app = QApplication([])
    window = SM2SignWidget()
    app.exec_()