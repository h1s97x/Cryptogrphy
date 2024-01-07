import logging

import random
from CryptographicProtocol import ModularPower, PrimeGen
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget
from Util import TypeConvert


class DHWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Diffie-Hellman")
        self.prime = 0
        self.primitive = 0
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Init",
                  plain_text_edits=[PlainTextEdit(id="Key-length", label="Bytes of Key (Decimal)", default_text="16"),
                                    PlainTextEdit(id="Prime", label="q (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="Primitive", label="a (Hex)", default_text="", read_only=True)],
                  buttons=[
                      Button(id="GenPars", name="PC Generate Parameters", clicked_function=self.gen_pars),
                      Button(id="InitCard", name="Init Card", clicked_function=self.init_card),
                      Button(id="CleanPar", name="Clean", clicked_function=self.clean_init_info),
                  ]),
            Group(name="Step 1: PC Calculate Y_A and Send It to Card",
                  plain_text_edits=[PlainTextEdit(id="X_A", label="X_A (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="Y_A", label="Y_A (Hex)", default_text="", read_only=True)],
                  buttons=[
                      Button(id="CalYA", name="Generate X_A and Calculate Y_A",
                             clicked_function=self.gen_xa_and_cal_ya),
                      Button(id="SendYA", name="Send Y_A to Card",
                             clicked_function=self.send_ya_to_card),
                      Button(id="CleanA", name="Clean", clicked_function=self.clean_a),
                  ]),
            Group(name="Step 2: PC Get Y_B from Card",
                  plain_text_edits=[PlainTextEdit(id="Y_B", label="Y_B (Hex)", default_text="", read_only=True)],
                  buttons=[
                      Button(id="GetYB", name="Get Y_B", clicked_function=self.get_yb_from_card),
                      Button(id="CleanB", name="Clean", clicked_function=self.clean_b),
                  ]),

            Group(name="Step 3: PC Calculate K_A",
                  plain_text_edits=[
                      PlainTextEdit(id="KeyPC", label="Key of PC (Hex)", default_text="", read_only=True)],
                  buttons=[
                      Button(id="PCCalKey", name="Calculate Key on PC", clicked_function=self.cal_key),
                      Button(id="CleanKey", name="Clean", clicked_function=self.clean_a_key),
                  ]),
            Group(name="God Vision",
                  plain_text_edits=[PlainTextEdit(id="X_B", label="X_B (Hex)", default_text="", read_only=True),
                                    PlainTextEdit(id="KeyCard", label="Key of Card (Hex)", default_text="",
                                                  read_only=True)],

                  buttons=[
                      Button(id="GetXB", name="Get X_B", clicked_function=self.get_xb_from_card),
                      Button(id="GetKeyCard", name="Get Key of Card", clicked_function=self.get_key_from_card),
                      Button(id="CleanKey", name="Clean", clicked_function=self.clean_b_key),
                  ]),
        ]

        # render user interface based on above-mentioned configurations
        self.render()
        self.logging("Diffie-Hellman protocol has been imported.\n")

    def deal_decimal(self, string):
        string = string.replace(' ', '')
        string = string.replace('\n', '')
        for i in range(len(string)):
            if string[i] < '0' or string[i] > '9':
                self.logging("The input of Key-length contains illegal characters.\n")
                self.pop_message_box("The input of Key-length contains illegal characters.")
                return None
        self.widgets_dict["Key-length"].set_text(string)
        return string

    def gen_pars(self):
        try:
            # print the login information to main logging widget
            self.logging("PC generates parameters.")

            if self.deal_decimal(self.widgets_dict["Key-length"].get_text()) is None:
                return

            length = int(self.widgets_dict["Key-length"].get_text())

            if length <= 0 or length > 128 or length % 4 != 0:
                self.logging("Key length must be between 4-128 and a multiple of 4.\n")
                self.pop_message_box("Key length must be between 4-128 and a multiple of 4.")
                return

            # get text from target widget
            keyBytes = self.widgets_dict["Key-length"].get_text()
            # 获取素数和本原根
            thread = PrimeGen.Thread(self, keyBytes, 0)
            thread.pars.connect(self.print_pars)
            # start thread
            thread.start()
        except Exception as e:
            self.logging_error(e)

    def print_pars(self, p, a):
        try:
            # 转成16进制的表示
            self.logging("Prime:                              " + p)
            self.widgets_dict["Prime"].set_text(p)
            self.logging("Primitive:                          " + a)
            self.widgets_dict["Primitive"].set_text(a)
            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    def init_card(self):
        try:
            length = int(self.widgets_dict["Key-length"].get_text())
            self.primitive = self.widgets_dict["Primitive"].get_text()
            self.prime = self.widgets_dict["Prime"].get_text()
            # init card
            self.logging("Init card.")
            # 将十六进制的数转成大数表示法,再转成可以和智能卡通讯的数据格式
            p_big = TypeConvert.str_to_hex_list(self.convert_big(self.prime))
            a = TypeConvert.str_to_hex_list(self.convert_big(self.primitive))

            # card生成随机数XB
            apdu_send = [0x00, 0x51, 0x00, 0x00, length]
            self.logging("(Init X_B)Send To Smart Card:       " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            # 发送p给card
            apdu_send = [0x00, 0x51, 0x01, 0x00, 0x80]
            apdu_send.extend(p_big)
            self.logging("(Init q)Send To Smart Card:         " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            if received_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            # 发送a给card
            apdu_send = [0x00, 0x51, 0x01, 0x01, 0x80]
            apdu_send.extend(a)
            self.logging("(Init a)Send To Smart Card:         " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    def gen_xa_and_cal_ya(self):
        try:
            # print the login information to main logging widget
            # 获取X_A长度
            length = int(self.widgets_dict["Key-length"].get_text())

            # 得到Alice的随机数
            XA = random.randint(1, 2 ** (8 * length) - 1)
            a = TypeConvert.str_to_int(self.widgets_dict["Primitive"].get_text())
            p = TypeConvert.str_to_int(self.widgets_dict["Prime"].get_text())
            if a is None or p is None:
                self.logging("Please generate parameters!")
                self.pop_message_box("Please generate parameters!")
                return
            thread = ModularPower.Thread(self, a, XA, p, length)
            thread.string.connect(self.print_ya)
            # start thread
            thread.start()

            XA = TypeConvert.int_to_str(XA, length)
            self.logging("PC calculate Y_A.")
            self.logging("X_A:                                " + XA)
            self.widgets_dict["X_A"].set_text(XA)

        except Exception as e:
            self.logging_error(e)

    def send_ya_to_card(self):
        try:
            Y_A = self.widgets_dict["Y_A"].get_text()
            # 判断Y_A是否有值
            if Y_A == "":
                self.logging("Y_A is empty!")
                self.pop_message_box("Y_A is empty!")
                return
            # send Y_A to card
            self.logging("PC sends Y_A to Card.")
            # 将十六进制的数转成大数表示法,再转成可以和智能卡通讯的数据格式
            Y_A = TypeConvert.str_to_hex_list(self.convert_big(Y_A))
            # 发送a给card
            apdu_send = [0x00, 0x51, 0x01, 0x02, 0x80]
            apdu_send.extend(Y_A)
            self.logging("(Send Y_A）Send To Smart Card:      " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            if received_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            self.logging("\n")
        except Exception as e:
            self.logging_error(e)

    def get_yb_from_card(self):
        try:
            length = int(self.widgets_dict["Key-length"].get_text())
            self.logging("PC get Y_B from card.")

            apdu_send = [0x00, 0x51, 0x01, 0x03, 0x00]
            self.logging("(Activate Enc)Send To Smart Card:   " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            if received_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            apdu_receive = [0x00, 0xC0, 0x00, 0x00, 0x80]
            self.logging("(Receive Result)Send To Smart Card: " + TypeConvert.hex_list_to_str(apdu_receive))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_receive])
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))
            self.logging("\n")

            YB_big = TypeConvert.hex_list_to_str(received_data[0][0:length])
            if YB_big == '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00':
                self.pop_message_box("Please click \"Init Card\" first")
                return 0
            # 将YB以标准格式输出
            YB = TypeConvert.hex_list_to_str(TypeConvert.str_to_hex_list(self.big_convert(YB_big)))
            self.widgets_dict["Y_B"].set_text(YB)
        except Exception as e:
            self.logging_error(e)

    def cal_key(self):
        try:
            # print the login information to main logging widget
            length = int(self.widgets_dict["Key-length"].get_text())
            # 得到Alice的随机数
            X_A = TypeConvert.str_to_int(self.widgets_dict["X_A"].get_text())
            Y_B = TypeConvert.str_to_int(self.widgets_dict["Y_B"].get_text())
            p = TypeConvert.str_to_int(self.widgets_dict["Prime"].get_text())
            if X_A is None or Y_B is None or p is None:
                self.logging("Please have X_A, Y_B and q!")
                self.pop_message_box("Please have X_A, Y_B and q!")
                return
            thread = ModularPower.Thread(self, Y_B, X_A, p, length)
            thread.string.connect(self.print_key)
            # start thread
            thread.start()
        except Exception as e:
            self.logging_error(e)

    def get_xb_from_card(self):
        try:
            length = int(self.widgets_dict["Key-length"].get_text())
            self.logging("PC get X_B from Card.")
            apdu_receive = [0x00, 0x51, 0x00, 0x01, 0x80]
            self.logging("(Get X_B)Send To Smart Card:        " + TypeConvert.hex_list_to_str(apdu_receive))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_receive])
            if received_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))
            self.logging("\n")
            XB_big = TypeConvert.hex_list_to_str(received_data[0][0:length])
            # 将XB以标准格式输出
            XB = TypeConvert.hex_list_to_str(TypeConvert.str_to_hex_list(self.big_convert(XB_big)))
            self.widgets_dict["X_B"].set_text(XB)
        except Exception as e:
            self.logging_error(e)

    def get_key_from_card(self):
        try:
            length = int(self.widgets_dict["Key-length"].get_text())
            self.logging("PC get key from card.")

            Y_A = self.widgets_dict["Y_A"].get_text()
            # send Y_A to card
            self.logging("PC sends Y_A to Card.")
            # 将十六进制的数转成大数表示法,再转成可以和智能卡通讯的数据格式
            Y_A = TypeConvert.str_to_hex_list(self.convert_big(Y_A))

            # 发送YA给card
            # apdu_send = [0x00, 0x51, 0x01, 0x01, 0x80]
            # apdu_send.extend(Y_A)
            # self.logging("(Send Y_A）Send To Smart Card:      " + TypeConvert.hex_list_to_str(apdu_send))
            # received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            # logging.info(received_data)
            # self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            # 计算key
            apdu_send = [0x00, 0x51, 0x01, 0x04, 0x00]
            self.logging("(Activate Enc)Send To Smart Card:   " + TypeConvert.hex_list_to_str(apdu_send))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_send])
            if received_data is None:
                self.pop_message_box(
                    ErrorType.SmartCardConnectError.value + " You should check the smart card and the smart card reader.")
                self.logging("\n")
                return
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))

            apdu_receive = [0x00, 0xC0, 0x00, 0x00, 0x80]
            self.logging("(Get K_B)Send To Smart Card:        " + TypeConvert.hex_list_to_str(apdu_receive))
            received_data = self.widgets_dict["SmartCard"].send_apdus([apdu_receive])
            logging.info(received_data)
            self.logging("Get Response From Smart Card:       " + TypeConvert.hex_list_to_str(received_data[0]))
            self.logging("\n")
            key_big = TypeConvert.hex_list_to_str(received_data[0][0:length])
            if key_big == '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00':
                self.pop_message_box("Please click \"Send Y_A to Card\" first")
                return 0
            # 将key以标准格式输出
            key = TypeConvert.hex_list_to_str(TypeConvert.str_to_hex_list(self.big_convert(key_big)))
            self.widgets_dict["KeyCard"].set_text(key)
        except Exception as e:
            self.logging_error(e)

    def print_ya(self, ya):
        self.logging("Y_A:                                " + ya)
        self.widgets_dict["Y_A"].set_text(ya)
        self.logging("\n")

    def print_key(self, key):
        self.logging("PC calculate K_A.")
        self.logging("K_A:                                " + key)
        self.widgets_dict["KeyPC"].set_text(key)
        self.logging("\n")

    # 平方乘算法实现模乘：返回值为x ** exp % n
    @staticmethod
    def pow_mod_n(x, exp, n):
        t = 1
        x_exp = x
        while exp > 0:
            if exp & 1 != 0:
                t *= x_exp
                t %= n
            x_exp *= x_exp
            x_exp %= n
            exp >>= 1
        return t

    # 将十六进制的数据转成大数表示法，结果输出为字符串
    @staticmethod
    def convert_big(num):
        num = list(num.replace(" ", ""))
        list_len = len(num)
        round_num = list_len // 8
        remain = list_len % 8
        new_num = []
        i = round_num - 1
        while i >= 0:
            for j in range(0, 8):
                new_num.append(num[remain + i * 8 + j])
            i -= 1
        for j in range(0, remain):
            new_num.append(num[j])
        fill_len = 256 - list_len
        for i in range(0, fill_len):
            new_num.append('0')
        return "".join(new_num)

    # 将大数表示法转成标准表示，结果输出为字符串
    @staticmethod
    def big_convert(num):
        num = list(num.replace(" ", ""))
        list_len = len(num)
        round_num = list_len // 8
        remain = list_len % 8
        new_num = []
        for j in range(0, remain):
            new_num.append(num[j])
        i = round_num - 1
        while i >= 0:
            for j in range(0, 8):
                new_num.append(num[remain + i * 8 + j])
            i -= 1
        return "".join(new_num)

    def print_result(self, result):
        self.logging("X_A:                          " + result)
        self.widgets_dict["X_A"].set_text(result)

    # clean widget text
    def clean_init_info(self):
        self.widgets_dict["Prime"].set_text("")
        self.widgets_dict["Primitive"].set_text("")

    # clean widget text
    def clean_a(self):
        self.widgets_dict["X_A"].set_text("")
        self.widgets_dict["Y_A"].set_text("")

    # clean widget text
    def clean_b(self):
        self.widgets_dict["Y_B"].set_text("")

    # clean widget text
    def clean_a_key(self):
        self.widgets_dict["KeyPC"].set_text("")

    # clean widget text
    def clean_b_key(self):
        self.widgets_dict["X_B"].set_text("")
        self.widgets_dict["KeyCard"].set_text("")
