import logging
import random
from . import Verify
from MathMagic.Modules.CryptographyModule import CryptographyWidget, Button, PlainTextEdit, IntroductionTab, SmartCardTab, SmartCard, Group, ErrorType
from Util import Path, TypeConvert


class VerifyWidget(CryptographyWidget):
    def __init__(self, parent):
        CryptographyWidget.__init__(self, parent)
        self.setWindowTitle("Verify")
        self.keyForPC = 0
        # set tabs widget configurations
        # link: link to the html file
        self.tabs_config = [IntroductionTab(
            link="file:///" + Path.MENU_DIRECTORY + "/CryptographicAlgorithm/CryptographicProtocol/Verify/html/index.html"),
            SmartCardTab()]
        # set smart card  widget configurations
        self.smart_card_config = SmartCard()
        # set groups configurations
        # set plain text edit component configurations
        # set button component configurations
        # id: the identity of the component
        # clicked_function: execute the function after the button clicked
        self.groups_config = [
            Group(name="",
                  plain_text_edits=[PlainTextEdit(id="KeyForPC", label="Key for PC (Hex)",
                                                  default_text="00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")],
                  buttons=[
                      Button(id="InitKeyForPC", name="Init", clicked_function=self.init_key_for_pc),
                      Button(id="GetKeyForPC", name="Get", clicked_function=self.get_key_for_pc),
                      Button(id="CleanKeyForPC", name="Clean", clicked_function=self.key_for_pc_clean)]
                  ),
            Group(name="",
                  plain_text_edits=[PlainTextEdit(id="KeyForCard", label="Key for Card (Hex)",
                                                  default_text="00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")],
                  buttons=[
                      Button(id="InitKeyForCard", name="Init", clicked_function=self.init_key_for_card),
                      Button(id="GetKeyForCard", name="Get", clicked_function=self.get_key_for_card),
                      Button(id="CleanKeyForCard", name="Clean", clicked_function=self.key_for_card_clean)]
                  ),
            Group(name="Step 1: PC Send Challenge to Card",
                  plain_text_edits=[PlainTextEdit(id="Challenge", label="Challenge (Hex)",
                                                  default_text="FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00")],
                  buttons=[
                      Button(id="ChallengeGenerate", name="Generate Challenge",
                             clicked_function=self.generate_challenge),
                      Button(id="ChallengeSend", name="Send Challenge", clicked_function=self.send_challenge),
                      Button(id="CleanChallenge", name="Clean", clicked_function=self.challenge_clean)
                  ]),
            Group(name="Step 2: PC Get Response from Card",
                  plain_text_edits=[PlainTextEdit(id="Response", label="Response (Hex)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="GetResponse", name="Get Response", clicked_function=self.get_response),
                      Button(id="CleanResponse", name="Clean", clicked_function=self.response_clean)
                  ]),
            Group(name="Step 3: Verify",
                  plain_text_edits=[PlainTextEdit(id="_Challenge", label="Challenge to be Verified (Hex)",
                                                  default_text=""),
                                    PlainTextEdit(id="_Response", label="Response to be Verified (Hex)",
                                                  default_text=""),
                                    PlainTextEdit(id="DecryptionResult", label="Decryption Result (Hex)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="VerifyResult", label="Verify Result",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="Verify", name="Verify", clicked_function=self.verify),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.verify_clean)
                  ])
        ]
        # render user interface based on above-mentioned configurations
        self.render()
        self.logging("Verify protocol has been imported.\n")

    def init_key_for_pc(self):
        try:
            self.logging("Init key for PC.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["KeyForPC"].get_text(), 'Key For PC'):
                return
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["KeyForPC"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key for PC\" input box.")
                self.logging("\n")
                return
            temp = len(key_list)
            if temp != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key for PC\" input box.")
                self.logging("\n")
                return
            # get text from target widget
            # then convert str to int
            self.keyForPC = TypeConvert.str_to_int(self.widgets_dict["KeyForPC"].get_text())
            self.widgets_dict["KeyForPC"].set_text(TypeConvert.int_to_str(self.keyForPC, 16))
            self.logging("Key for PC: " + TypeConvert.int_to_str(self.keyForPC, 16))
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    # Get key for pc
    def get_key_for_pc(self):
        self.logging("Get key from PC.")
        self.widgets_dict["KeyForPC"].set_text(TypeConvert.int_to_str(self.keyForPC, 16))
        self.logging("key for PC:   " + TypeConvert.int_to_str(self.keyForPC, 16))
        self.logging("\n")

    # clean widget text
    def key_for_pc_clean(self):
        self.widgets_dict["KeyForPC"].set_text("")

    def init_key_for_card(self):
        try:
            self.logging("Init key for card.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["KeyForCard"].get_text(), 'Key For Card'):
                return
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["KeyForCard"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key for Card\" input box.")
                self.logging("\n")
                return
            temp = len(key_list)
            if temp != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key for Card\" input box.")
                self.logging("\n")
                return
            # get text from target widget
            # then convert str to int
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["KeyForCard"].get_text())
            self.widgets_dict["KeyForCard"].set_text(TypeConvert.hex_list_to_str(key_list))
            apdu_send = [0x00, 0x50, 0x00, 0x00, len(key_list)]
            apdu_send.extend(key_list)
            # smart card communication
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            if received_data is None:
                self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(received_data[0]))
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    # Get key for card
    def get_key_for_card(self):
        try:
            self.logging("Get key from card.")
            apdu_receive = [0x00, 0x50, 0x00, 0x01, 0x10]
            # smart card communication
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdu_receive))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_receive])
            if received_data is None:
                self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(received_data[0]))
            self.widgets_dict["KeyForCard"].set_text(TypeConvert.hex_list_to_str(received_data[0][0:16]) + "\n")
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    # clean widget text
    def key_for_card_clean(self):
        self.widgets_dict["KeyForCard"].set_text("")

    def generate_challenge(self):
        try:
            self.logging("Step 1.1: Computer generate challenge.")
            challenge_list = []
            for i in range(0, 16, 1):
                r = random.randint(0, 255)
                challenge_list.append(r)
            # format input
            self.widgets_dict["Challenge"].set_text(TypeConvert.hex_list_to_str(challenge_list))
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    # encrypt on smart card
    def send_challenge(self):
        try:
            self.logging("Step 1.2: Computer send challenge to smart card.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["Challenge"].get_text(), 'Challenge'):
                return
            challenge_list = TypeConvert.str_to_hex_list(self.widgets_dict["Challenge"].get_text())
            if challenge_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Challenge\" input box.")
                self.logging("\n")
                return
            temp = len(challenge_list)
            if temp != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Challenge\" input box.")
                self.logging("\n")
                return
            # format input
            challenge_list = TypeConvert.str_to_hex_list(self.widgets_dict["Challenge"].get_text())
            self.widgets_dict["Challenge"].set_text(TypeConvert.hex_list_to_str(challenge_list))
            apdu_send = [0x00, 0x50, 0x01, 0x00, len(challenge_list)]
            apdu_send.extend(challenge_list)
            # smart card communication
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            if received_data is None:
                self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(received_data[0]))
            self.logging("\n")
            self.widgets_dict["_Challenge"].set_text(self.widgets_dict["Challenge"].get_text())
        except Exception as e:
            self.logging_error(e)

    # encrypt on smart card
    def get_response(self):
        try:
            self.logging("Step 2: Computer get response from smart card.")
            apdu_receive = [0x00, 0xc0, 0x00, 0x00, 0x10]
            # smart card communication
            self.logging("Send To Smart Card:           " + TypeConvert.hex_list_to_str(apdu_receive))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_receive])
            if received_data is None:
                self.pop_message_box(ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card: " + TypeConvert.hex_list_to_str(received_data[0]))
            temp = received_data[0][0:16]
            temp = TypeConvert.hex_list_to_str(temp)
            self.widgets_dict["Response"].set_text(temp + "\n")
            self.widgets_dict["_Response"].set_text(temp)
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    # verify on computer
    def verify(self):
        try:
            self.logging("Step 3: Computer verify on your computer.")
            if not self.error_check_str_to_hex_list(self.widgets_dict["KeyForPC"].get_text(), 'Key For PC'):
                return
            key_list = TypeConvert.str_to_hex_list(self.widgets_dict["KeyForPC"].get_text())
            if key_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Key for PC\" input box.")
                self.logging("\n")
                return
            temp = len(key_list)
            if temp != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Key for PC\" input box.")
                self.logging("\n")
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Challenge"].get_text(), 'Challenge'):
                return
            challenge_list = TypeConvert.str_to_hex_list(self.widgets_dict["_Challenge"].get_text())
            if challenge_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Challenge to be Verified\" input box.")
                self.logging("\n")
                return
            temp1 = len(challenge_list)
            if temp1 != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Challenge to be Verified\" input box.")
                self.logging("\n")
                return
            if not self.error_check_str_to_hex_list(self.widgets_dict["_Response"].get_text(), 'Response'):
                return
            response_list = TypeConvert.str_to_hex_list(self.widgets_dict["_Response"].get_text())
            if response_list is None:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Response to be Verified\" input box.")
                self.logging("\n")
                return
            temp2 = len(response_list)
            if temp2 != 16:
                self.pop_message_box(ErrorType.LengthError.value + "You should check the \"Response to be Verified\" input box.")
                self.logging("\n")
                return
            # get text from target widget
            # then convert str to int
            key = TypeConvert.str_to_int(self.widgets_dict["KeyForPC"].get_text())
            response = TypeConvert.str_to_int(self.widgets_dict["_Response"].get_text())
            challenge = TypeConvert.str_to_int(self.widgets_dict["_Challenge"].get_text())
            self.widgets_dict["KeyForPC"].set_text(TypeConvert.int_to_str(key, 16))
            self.widgets_dict["_Response"].set_text(TypeConvert.int_to_str(response, 16))
            self.widgets_dict["_Challenge"].set_text(TypeConvert.int_to_str(challenge, 16))
            self.logging("KeyForPC:                 " + TypeConvert.int_to_str(key, 16))
            self.logging("Response to be verified:  " + TypeConvert.int_to_str(response, 16))
            self.logging("Challenge to be verified: " + TypeConvert.int_to_str(response, 16))
            thread = Verify.Thread(self, response, key, challenge)
            thread.final_result.connect(self.widgets_dict["DecryptionResult"].set_text)
            thread.logging_info.connect(self.logging)
            thread.verified_result.connect(self.widgets_dict["VerifyResult"].set_text)
            thread.start()
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    # clean widget text
    def challenge_clean(self):
        self.widgets_dict["Challenge"].set_text("")

    # clean widget text
    def response_clean(self):
        self.widgets_dict["Response"].set_text("")

    # clean widget text
    def verify_clean(self):
        self.widgets_dict["DecryptionResult"].set_text("")
        self.widgets_dict["VerifyResult"].set_text("")

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
