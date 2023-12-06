# 去掉比特串前面的0
def remove_0b_at_beginning(a):
    if a[0:2] == '0b':
        a = a[2:len(a)]
    return a


def padding_0_to_length(S, length):
    temp = S
    S = ''
    if temp[0:2] == '0b':
        S += '0b'
        temp = temp[2:len(temp)]
    for i in range(0, length - len(temp)):
        S += '0'
    for i in range(0, len(temp)):
        S = S + temp[i]
    return S
