import logging


def is_hex_string(string):
    for i in string:
        if ('0' > i or '9' < i) and ('A' > i or 'F' < i) and ('a' > i or 'f' < i):
            return 1
    return 0


def str_to_hex_list(text: str):
    str_no_space = text.replace(" ", "")
    str_no_space = str_no_space.replace("\n", "")
    length = len(str_no_space)
    if is_hex_string(str_no_space):
        logging.debug("Characters error")
        return 'ERROR_CHARACTER'
    if not (length % 2 == 0):
        logging.debug("Length error")
        return 'ERROR_LENGTH'
    length = int(length / 2)
    hex_list = []
    try:
        for i in range(length):
            temp = str_no_space[i * 2:i * 2 + 2]
            hex_list.append(int(temp, 16))
        return hex_list
    except Exception as e:
        return None


# error_check for ui
# def error_check_str_to_hex_list(self, text: str, input_name: str) -> bool:
#     if TypeConvert.str_to_hex_list(text) == 'ERROR_CHARACTER':
#         self.logging(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
#         self.pop_message_box(ErrorType.CharacterError.value + 'You should check the \"' + input_name + '\" input box.\n')
#         return False
#     elif TypeConvert.str_to_hex_list(text) == 'ERROR_LENGTH':
#         self.logging(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.\n')
#         self.pop_message_box(ErrorType.LengthError.value + input_name + 'length must be a multiple of 2.')
#         return False
#     elif TypeConvert.str_to_hex_list(text) is None:
#         return False
#     else:
#         return True


def int_to_str(int_data: int, length: int):
    str_data = hex(int_data)
    str_data = str_data.replace("0x", "")
    n_z = length * 2 - len(str_data)
    for i in range(0, n_z, 1):
        str_data = "0" + str_data
    str_data = str_data.upper()
    data_out = ""
    for i in range(0, length * 2, 2):
        if i == length * 2 - 1:
            data_out += str_data[i:i + 2]
        else:
            data_out = data_out + str_data[i: i + 2] + " "
    return data_out.strip()

# 原本的程序是用smartcard库的util，这里需要自己实现一下
# def hex_list_to_str(hex_list: list):
#     try:
#         temp = util.toHexString(hex_list)
#         return temp
#     except Exception as e:
#         return None
def hex_list_to_str(hex_list):
    try:
        str_list = [format(num, '02x') for num in hex_list]
        temp = ''.join(str_list)
        return temp
    except Exception as e:
        return None

def str_to_int(text: str):
    str_with_out_space = text.replace(" ", "")
    str_with_out_space = str_with_out_space.replace("\n", "")
    length = len(str_with_out_space)
    if not (length % 2 == 0):
        logging.debug("Length error")
        return None
    text = "0x" + str_with_out_space
    try:
        int_data = int(text, 16)
        return int_data
    except Exception as e:
        logging.debug("Convert failed")
        logging.debug(e)
        return None


def int_to_hex_list(int_data, length):
    hex_list = []
    for i in range(length):
        byte = (int_data >> (8 * (length - (i + 1)))) & 0xFF
        hex_list.append(byte)
    return hex_list


def hex_list_to_int(hex_list):
    int_data = 0
    for i in range(len(hex_list)):
        int_data |= hex_list[len(hex_list) - i - 1] << (8 * i)
    return int_data

def int_to_bytes(i, min_size = None):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    b = i.to_bytes((i.bit_length()+7)//8, byteorder='big')
    if min_size != None and len(b) < min_size:
        b = b'\x00'*(min_size-len(b)) + b
    return b