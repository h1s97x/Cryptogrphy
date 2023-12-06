from .Integer import isPrime_MR, is_Power_of_two

# 有限域参数 q #
q = 0
q_prime = False
q_2m = False


def is_q_prime():
    return q_prime


def is_q_power_of_two():
    return q_2m


def set_q(a):
    global q
    global q_prime
    global q_2m
    if isPrime_MR(a, 15):
        q = a
        q_prime = True
        if is_Power_of_two(q):
            q_2m = True
        else:
            q_2m = False
    elif is_Power_of_two(a):
        q = a
        q_2m = True
        if isPrime_MR(q, 15):
            q_prime = True
        else:
            q_prime = False
    else:
        print("*** ERROR: q必须为奇素数或2的幂 *** function: set_q")


def get_q():
    return q


# 二元阔域中做模数的素多项式 #
fx = '0b0'


def set_fx(a):
    global fx
    if a[0:2] != '0b':
        print("*** ERROR: 参数必须是比特串 *** function: set_fx")
    else:
        for i in range(2, len(a)):
            if a[i] != '0' and a[i] != '1':
                print("*** ERROR: 参数必须是比特串 *** function: set_fx ***")
        fx = a


def get_fx():
    return fx


### test set_fx ###
# print(fx)
# set_fx('0b10101111')
# print(fx)

# 椭圆曲线参数 #
a = 0
b = 0


def set_a(ia):
    global a
    a = ia


def get_a():
    return a


def set_b(ib):
    global b
    b = ib


def get_b():
    return b


n = 0


def set_n(a):
    global n
    n = a


def get_n():
    return n


Gx = 0


def set_Gx(a):
    global Gx
    Gx = a


def get_Gx():
    return Gx


Gy = 0


def set_Gy(a):
    global Gy
    Gy = a


def get_Gy():
    return Gy


h = -1


def set_h(a):
    global h
    h = a


def get_h():
    return h


# 设置参数 #
def set_parameters(parameters):
    set_q(parameters['q'])
    if is_q_power_of_two():
        set_fx(parameters['f(x)'])
    set_a(parameters['a'])
    set_b(parameters['b'])
    set_n(parameters['n'])
    set_Gx(parameters['Gx'])
    set_Gy(parameters['Gy'])
    set_h(parameters['h'])


def get_parameters():
    param = {
        'q': get_q(),
        'a': get_a(),
        'b': get_b(),
        'n': get_n(),
        'Gx': get_Gx(),
        'Gy': get_Gy(),
        'h': get_h()
    }
    if is_Power_of_two(get_q()):
        dict_f = {'f(x)': get_fx()}
        param.update(dict_f)
    return param


# 从读配置文件 #
def read_config_file(filename):
    fo = open(filename, "ab+")
    fl = fo.tell()
    fo.seek(0, 0)
    config = eval(fo.read(fl))
    fo.close()
    return config


# 设置为默认参数 #
def default_config(num: int = 0):
    """
    num=0时为SM2推荐参数
    num=1时为Fp-256参数
    """
    # SM2 推荐参数
    default = {'q': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
               'f(x)': 'NULL',
               'a': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
               'b': 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
               'h': 1,
               'Gx': 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7,
               'Gy': 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0,
               'n': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
               }
    # Fp-256
    parameters = {'q': 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
                  'f(x)': 'NULL',
                  'a': 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
                  'b': 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
                  'h': 1,
                  'Gx': 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
                  'Gy': 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2,
                  'n': 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
                  }
    if num == 0:
        set_parameters(default)
    elif num == 1:
        set_parameters(parameters)


def get_v():
    return 256
