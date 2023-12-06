import math
import random
from MathMagic.Modules.CryptographyModule import CryptographyWidget, Button, PlainTextEdit, IntroductionTab, Group, ErrorType
from Util import Path


class MillionaireWidget(CryptographyWidget):
    def __init__(self, parent):
        CryptographyWidget.__init__(self, parent)
        self.setWindowTitle("Millionaire")
        self.keyForPC = 0
        # set tabs widget configurations
        # link: link to the html file
        self.tabs_config = [IntroductionTab(
            link="file:///" + Path.MENU_DIRECTORY + "/CryptographicAlgorithm/CryptographicProtocol/Millionaire/html/index.html")]
        # set smart card  widget configurations
        # self.smart_card_config = SmartCard()
        # set groups configurations
        # set plain text edit component configurations
        # set button component configurations'
        # id: the identity of the component
        # clicked_function: execute the function after the button clicked
        self.groups_config = [
            Group(name="Step 1: Get Data",
                  plain_text_edits=[PlainTextEdit(id="WangAssets", label="Wang's assets (Millions)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="LiAssets", label="Li's assets (Millions)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="WangPublicKey", label="Wang's PublicKey (Int)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="WangPrivateKey", label="Wang's PrivateKey (Int)",
                                                  default_text="", read_only=True)
                                    ],
                  buttons=[
                      Button(id="GetAssets", name="Get Assets", clicked_function=self.get_assets),
                      Button(id="GetKeyForWang", name="Get Key for Wang", clicked_function=self.get_key_for_wang),
                      Button(id="CleanStep1", name="Clean", clicked_function=self.clean_step1)]
                  ),
            Group(name="Step 2: Millionaire Li",
                  plain_text_edits=[PlainTextEdit(id="RandomInteger", label="X (Int)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="EncryptedNumber", label="C (Int)",
                                                  default_text="", read_only=True)
                                    ],
                  buttons=[
                      Button(id="GetRandom", name="Get X", clicked_function=self.get_random_integer),
                      Button(id="EncryptForPC", name="Encrypt (PC)", clicked_function=self.encrypt_and_send_to_wang),
                      Button(id="CleanStep2", name="Clean", clicked_function=self.clean_step2)]
                  ),
            Group(name="Step 3: Millionaire Wang",
                  plain_text_edits=[PlainTextEdit(id="C", label="C List (List)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="DecryptNumber", label="C_decrypt List (List)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="PrimeNumber", label="P (Int)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="D", label="D List (List)",
                                                  default_text="", read_only=True)
                                    ],
                  buttons=[
                      Button(id="Decrypt", name="Decrypt (PC)",
                             clicked_function=self.decrypted_for_pc),
                      Button(id="GetPrimeNumber", name="Get P and D List",
                             clicked_function=self.get_prime_number_and_d),
                      Button(id="CleanStep3", name="Clean", clicked_function=self.clean_step3)
                  ]),
            Group(name="Step 4: Millionaire Li",
                  plain_text_edits=[PlainTextEdit(id="ListfromWang", label="D_new List (List)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="XmodP", label="X mod P (Int)",
                                                  default_text="", read_only=True),
                                    PlainTextEdit(id="VerifyResult", label="Verify (Str)",
                                                  default_text="", read_only=True)
                                    ],
                  buttons=[
                      Button(id="GetListfromWang", name="Get D_new List", clicked_function=self.get_d_new),
                      Button(id="GetXmodP", name="Get XmodP", clicked_function=self.get_xmodp),
                      Button(id="Verify", name="Verify", clicked_function=self.verify),
                      Button(id="CleanStep4", name="Clean", clicked_function=self.clean_step4)
                  ])
        ]
        # render user interface based on above-mentioned configurations
        self.render()
        self.logging("Millionaire protocol has been imported.\n")

    def get_assets(self):
        i = random.randint(1, 9)
        j = random.randint(1, 9)
        self.logging("Wang's assets are " + str(i) + " million.")
        self.logging("Li's assets are " + str(j) + " million.\n")
        self.widgets_dict["WangAssets"].set_text(str(i))
        self.widgets_dict["LiAssets"].set_text(str(j))

    def get_key_for_wang(self):
        pbvk = build_key()
        pbk = (pbvk[0], pbvk[1])  # 公钥
        pvk = (pbvk[0], pbvk[2])  # 私钥
        self.logging("Li's public key is " + str(pbk) + " .")
        self.logging("Li's private key " + str(pvk) + " .\n")
        self.widgets_dict["WangPublicKey"].set_text(str(pbk))
        self.widgets_dict["WangPrivateKey"].set_text(str(pvk))

    def get_random_integer(self):
        x = random.randint(1, 100)
        self.logging("Random integer is " + str(x) + " .\n")
        self.widgets_dict["RandomInteger"].set_text(str(x))

    def encrypt_and_send_to_wang(self):
        x = int(self.widgets_dict["RandomInteger"].get_text())
        pbk = self.widgets_dict["WangPublicKey"].get_text()
        if x == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"RandomInteger\" input box.")
            self.logging("\n")
            return
        if pbk == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"WangPublicKey\" input box.")
            self.logging("\n")
            return
        pbk = pbk.replace(' ', '').replace('(', '').replace(')', '')
        pbk = pbk.split(',')
        pbk = (int(pbk[0]), int(pbk[1]))
        k = rsa_encrypt(x, pbk)
        # print("大整数加密后得密文K: %s" % (k))
        self.logging("Encrypted number is " + str(k) + " .")
        self.widgets_dict["EncryptedNumber"].set_text(str(k))
        self.logging('\n')
        j = int(self.widgets_dict["LiAssets"].get_text())
        if j == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"LiAssets\" input box.")
            self.logging("\n")
            return
        c = k - j
        c_array = []
        for i in range(0, 10):
            c_array.append(c + i + 1)
        self.logging("C list is " + str(c_array) + " .\n")
        self.widgets_dict["C"].set_text(str(c_array))

    def decrypted_for_pc(self):
        pvk = self.widgets_dict["WangPrivateKey"].get_text()
        if pvk == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"WangPrivateKey\" input box.")
            self.logging("\n")
            return
        pvk = pvk.replace(' ', '').replace('(', '').replace(')', '')
        pvk = pvk.split(',')
        pvk = (int(pvk[0]), int(pvk[1]))
        c_array = self.widgets_dict["C"].get_text()
        if c_array == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"C\" input box.")
            self.logging("\n")
            return
        c_array = c_array.replace(' ', '').replace('[', '').replace(']', '')
        c_array = c_array.split(',')
        c_decrypt = []
        for i in range(0, 10):
            c_array[i] = int(c_array[i])
            c_decrypt.append(rsa_decrypt(c_array[i], pvk))
        self.logging("Decrypt list is " + str(c_decrypt) + " .\n")
        self.widgets_dict["DecryptNumber"].set_text(str(c_decrypt))

    def get_prime_number_and_d(self):
        c_decrypt = self.widgets_dict["DecryptNumber"].get_text()
        X = self.widgets_dict["RandomInteger"].get_text()
        if c_decrypt == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"DecryptNumber\" input box.")
            self.logging("\n")
            return
        if X == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"RandomInteger\" input box.")
            self.logging("\n")
            return
        c_decrypt = c_decrypt.replace(' ', '').replace('[', '').replace(']', '')
        c_decrypt = c_decrypt.split(',')
        for i in range(0, 10):
            c_decrypt[i] = int(c_decrypt[i])
        while True:
            p = random.randint(2, int(X) - 1)
            if is_prime(p):
                break
        d_array = []
        for k in range(0, 10):
            d_array.append(c_decrypt[k] % p)
        self.logging("P is " + str(p) + " .")
        self.logging('\n')
        self.widgets_dict["PrimeNumber"].set_text(str(p))
        self.logging("D list is " + str(d_array) + " .\n")
        self.widgets_dict["D"].set_text(str(d_array))

    def get_d_new(self):
        w = int(self.widgets_dict["WangAssets"].get_text())
        if w == '':
            self.pop_message_box(
                ErrorType.NotMeetRequirementError.value + "You should check the \"WangAssets\" input box.")
            self.logging("\n")
            return
        d_add = self.widgets_dict["D"].get_text()
        if d_add == '':
            self.pop_message_box(
                ErrorType.NotMeetRequirementError.value + "You should check the \"D\" input box.")
            self.logging("\n")
            return
        d_add = d_add.replace(' ', '').replace('[', '').replace(']', '')
        d_add = d_add.split(',')
        for i in range(0, 10):
            d_add[i] = int(d_add[i])
            if i >= w:
                d_add[i] += 1
        self.logging("List from wang is " + str(d_add) + " .\n")
        self.widgets_dict["ListfromWang"].set_text(str(d_add))

    def get_xmodp(self):
        x = int(self.widgets_dict["RandomInteger"].get_text())
        if x == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"RandomInteger\" input box.")
            self.logging("\n")
            return
        p = int(self.widgets_dict["PrimeNumber"].get_text())
        if p == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"PrimeNumber\" input box.")
            self.logging("\n")
            return
        x_mod_p = x % p
        self.logging("X mod p is " + str(x_mod_p) + " .\n")
        self.widgets_dict["XmodP"].set_text(str(x_mod_p))

    def verify(self):
        j = int(self.widgets_dict["LiAssets"].get_text())
        if j == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"LiAssets\" input box.")
            self.logging("\n")
            return
        xmodp = int(self.widgets_dict["XmodP"].get_text())
        if xmodp == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"XmodP\" input box.")
            self.logging("\n")
            return
        d = self.widgets_dict["ListfromWang"].get_text()
        if d == '':
            self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"ListfromWang\" input box.")
            self.logging("\n")
            return
        d = d.replace(' ', '').replace('[', '').replace(']', '')
        d = d.split(',')
        for i in range(0, 10):
            d[i] = int(d[i])
        if d[j - 1] == xmodp:
            self.logging("Wang>=Li. \n")
            self.widgets_dict["VerifyResult"].set_text('i>=j.')
            # print("i>=j,即王比李有钱或一样有钱")
        else:
            # print("i<j,即李比王有钱")
            self.logging("Wang<Li. \n")
            self.widgets_dict["VerifyResult"].set_text('i<j.')

    # clean widget text
    def clean_step1(self):
        self.widgets_dict["WangAssets"].set_text("")
        self.widgets_dict["LiAssets"].set_text("")
        self.widgets_dict["WangPublicKey"].set_text("")
        self.widgets_dict["WangPrivateKey"].set_text("")

    # clean widget text
    def clean_step2(self):
        self.widgets_dict["RandomInteger"].set_text("")
        self.widgets_dict["EncryptedNumber"].set_text("")
        self.widgets_dict["C"].set_text("")

    # clean widget text
    def clean_step3(self):
        self.widgets_dict["DecryptNumber"].set_text("")
        self.widgets_dict["PrimeNumber"].set_text("")
        self.widgets_dict["D"].set_text("")

    # clean widget text
    def clean_step4(self):
        self.widgets_dict["ListfromWang"].set_text("")
        self.widgets_dict["XmodP"].set_text("")
        self.widgets_dict["VerifyResult"].set_text("")


# 获取小于等于指定数的素数数组
def get_prime_arr(max_num):
    prime_array = []
    for i in range(11, max_num):
        if is_prime(i):
            prime_array.append(i)
    return prime_array


# 判断是否为素数
def is_prime(num):
    for i in range(2, math.floor(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True


# 找出一个指定范围内与n互质的整数e
def find_pub_key(n, max_num):
    while True:
        # 这里是随机获取保证随机性
        e = random.randint(1, max_num)
        if gcd(e, n) == 1:
            break
    return e


# 求两个数的最大公约数
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


# 根据e*d mod s = 1,找出d
def find_pri_key(e, s):
    for d in range(100000000):  # 随机太难找，就按顺序找到d,range里的数字随意
        x = (e * d) % s
        if x == 1:
            return d


# 生成公钥和私钥
def build_key():
    prime_arr = get_prime_arr(50)
    p = random.choice(prime_arr)
    # 保证p和q不为同一个数
    while True:
        q = random.choice(prime_arr)
        if p != q:
            break
    print("随机生成两个素数p和q. p=", p, " q=", q)
    n = p * q
    s = (p - 1) * (q - 1)

    # e = find_pub_key(s, 100)
    # print("根据e和(p-1)*(q-1))互质得到: e=", e)
    # d = find_pri_key(e, s)
    # print("根据(e*d) 模 ((p-1)*(q-1)) 等于 1 得到 d=", d)

    # 找出一个指定范围内与n互质的整数e
    while True:
        # 这里是随机获取保证随机性
        e = random.randint(1, n)
        if gcd(e, s) == 1 and e < n:
            break
    # e = find_pub_key(s, 100)
    print("根据e和(p-1)*(q-1))互质得到: e=", e)

    for k in range(100000000):  # 随机太难找，就按顺序找到d,range里的数字随意
        x = (e * k) % s
        if x == 1:
            d = k
            break
    print("根据(e*d) 模 ((p-1)*(q-1)) 等于 1 得到 d=", d)
    print("公钥:   n=", n, "  e=", e)
    print("私钥:   n=", n, "  d=", d)
    return n, e, d


# 加密
def rsa_encrypt(content, ned):
    # 密文B = 明文A的e次方 模 n， ned为公钥
    # content就是明文A，ned【1】是e， ned【0】是n
    B = pow(content, ned[1]) % ned[0]
    return B


# 解密
def rsa_decrypt(encrypt_result, ned):
    # 明文C = 密文B的d次方 模 n， ned为私钥匙
    # encrypt_result就是密文, ned【1】是d, ned【0】是n
    C = pow(encrypt_result, ned[1]) % ned[0]
    return C
