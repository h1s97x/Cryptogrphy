import math
import random
from MathMagic.Modules.CryptographyModule import CryptographyWidget, Button, PlainTextEdit, IntroductionTab, ErrorType, KeyGroup, Group, ComboBox
from Util import Path


class ZKPWidget(CryptographyWidget):
    def __init__(self, parent):
        CryptographyWidget.__init__(self, parent)
        self.setWindowTitle("Zero-Knowledge Proof")
        self.keyForPC = 0
        # set tabs widget configurations
        # link: link to the html file
        self.tabs_config = [IntroductionTab(
            link="file:///" + Path.MENU_DIRECTORY + "/CryptographicAlgorithm/CryptographicProtocol/Zero_Knowledge_Proof/html/index.html")]
        # set smart card  widget configurations
        # self.smart_card_config = SmartCard()
        # set groups configurations
        # set plain text edit component configurations
        # set button component configurations'
        # id: the identity of the component
        # clicked_function: execute the function after the button clicked
        self.groups_config = [
            KeyGroup(name="Known or Unknown",
                     combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                                         items=["Known", "Unknown"])]  # changed_function=self.clean_step2
                     ),
            Group(name="Select the number of verifications",
                  plain_text_edits=[PlainTextEdit(id="SelectNumber", label="Select Number (Int)",
                                                  default_text="")],
                  buttons=[Button(id="Verify", name="Verify", clicked_function=self.verify_result)]
                  ),
            Group(name="Verification results",
                  plain_text_edits=[PlainTextEdit(id="VerifyResult", label="Result (Str)",
                                                  default_text="")],
                  buttons=[Button(id="CleanResult", name="Clean Result", clicked_function=self.clean_result)
                           ])
        ]
        # render user interface based on above-mentioned configurations
        self.render()
        self.logging("Zero-Knowledge Proof has been imported.\n")

    # clean widget text
    def verify_result(self):
        try:
            known_or_unknown = int(self.widgets_dict["ComboBox"].get_index())
            select_num = self.widgets_dict["SelectNumber"].get_text()
            select_num = select_num.replace(' ', '')
            self.widgets_dict["SelectNumber"].set_text(select_num)
            if select_num == '':
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Select Number\" input box.")
                return
            if int(select_num) <= 0 or int(select_num) >= 1000:
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "The number of verifications must be between 1-1000.")
                return

            known_num = 0
            for i in range(0, int(select_num)):
                if known_or_unknown == 0:
                    self.logging("Verification result " + str(i + 1) + ": can.")
                    known_num += 1
                if known_or_unknown == 1:
                    p = random.randint(1, 100)
                    if p % 2 == 0:
                        self.logging("Verification result " + str(i + 1) + ": can.")
                        known_num += 1
                    else:
                        self.logging("Verification result " + str(i + 1) + ": cannot.")
            self.logging("\n")
            self.widgets_dict["VerifyResult"].set_text(
                "Verification result shows that the number of 'can' is " + str(known_num)
                + ", and the number of 'cannot' is " + str(int(select_num) - known_num) + ". \n")
        except Exception as e:
            self.logging('Error:' + str(e) + '\n')

    # clean widget text
    def clean_result(self):
        self.widgets_dict["VerifyResult"].set_text("")


# 获取小于等于指定数的素数数组
def get_prime_arr(max_num):
    prime_array = []
    for i in range(2, max_num):
        if is_prime(i):
            prime_array.append(i)
    return prime_array


# 判断是否为素数
def is_prime(num):
    for i in range(2, math.floor(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True
