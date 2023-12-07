## Version1.0 - 2023.12.05
### BUG



1.Frequency_Analysis_ui有问题，待修复。
self.widgets_dict["IntermediateValueTab"]
IntermediateValueTab是菜单相关的

```
thread.logging_result.connect(self.logging.log_decrypt_multi)
```

缺少log_decrypt_multi方法？变量？

2.Crypto-1_ui

```
# 不知道这里的意义，不会改
# thread.key_stream_result.connect(self.logging)
```

3.Block_Mode_ui.py

涉及到类型转换，TypeConvert.py里有一个方法是基于smartcard的

TypeConvert.py

```
原本的程序是用smartcard库的util，这里需要自己实现一下
def hex_list_to_str(hex_list: list):
    try:
        temp = util.toHexString(hex_list)
        return temp
    except Exception as e:
        return None
```

更新后：

```
def hex_list_to_str(hex_list):
    try:
        str_list = [format(num, '02x') for num in hex_list]
        temp = ''.join(str_list)
        return temp
    except Exception as e:
        return None
```

能够正常运行，但是执行线程后程序会退出。

```
thread = Block_Mode.Thread(self, plaintext_str, key_str, mode_selected, 0, len(plaintext_list))
# thread.intermediate_value.connect(self.widgets_dict["IntermediateValueTab"].append)
thread.final_result.connect(self.func_encrypt)
# start Block Mode thread
thread.start()
```

经查，是在Block_Mode.py里

```
def int_to_matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[int(i / 4)].append(byte)
    return matrix
```

最后转换报错，出现了NoneType也就是空数据

4.ECDSA_ui、ElGamal_ui

ECDSA.py

```
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
```

ElGamal.py

```
from Crypto.PublicKey import RSA
```

使用了Crypto类，ModuleNotFoundError: No module named 'Crypto'

之前就没有解决的问题。

5.RSA_Sign_ui、SM2_Sign_ui

```
# encrypt on smart card
def card_verify(self)
```

6.Password_system_ui

```
combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                    items=["SHA1", "SHA256", "SHA3-256", "MD5", "SM3"])]
```

缺少changed_function

```
combo_widget.currentIndexChanged.connect(combo.changed_function)  # 添加这一行以关联信号和槽函数
```

7.CryptographicProtocol包

DH、Digital_Certificate等都需要和smartcard交互，这个包可以考虑不做

需要smartcard

## Version1.1 - 2023.12.06

新的修改：
1.在主窗口菜单栏整合了所有的子窗口；
2.导入优化。

### 导入优化

在把所有子窗口整合到主窗口时遇到的问题：

1.在项目头处导入子窗口类会报错：循环导入

```
File "E:\Document\OneDrive - mail.sdu.edu.cn\Desktop\pyqt5\Util\Modules.py", line 7, in <module>
    from ClassicCrypto.Hill_ui import HillWidget
ImportError: cannot import name 'HillWidget' from partially initialized module 'ClassicCrypto.Hill_ui' (most likely due to a circular import)
```

因此就需要延迟导入，即在需要的时候再导入：

[Python 中的延迟导入 (linux-console.net)](https://cn.linux-console.net/?p=26741)

那么解决方法就是在主窗口初始化菜单时再导入。

```
    def initUI(self):
        # 延迟导入
        import ClassicCrypto
        import BlockCipher
        import PublicKeyCryptography
        import StreamCipher
        import Hash
        # import CryptographicProtocol
        import MathematicalBasis
```



2.因为项目中包含多个子窗口且分散在不同的py模块里，如果按照

```
from ClassicCrypto.Hill_ui import HillWidget
```

这样的方式一个个导入，不仅写起来麻烦，同样会给以后的维护带来很大的弊端，而且不太符合编程的规范。因此有没有什么办法能够将一个软件包直接导入进来？

这就要提到init.py了，

***init**.py的作用
它的作用是在导入包时首先执行的。
假设在 exp.py 中写入 import one.exp1 ，那么会首先执行 **init**.py 文件，接着会执行exp1.py文件
如果不需要，**init**.py可以为空，也可以干脆不加入__init__.py*

```
# ClassicCrypto/__init__.py
from .Hill_ui import HillWidget
from .Caesar_ui import CaesarWidget
from .Enigma_ui import EnigmaWidget
from .Frequency_Analysis_ui import FAWidget
from .Monoalphabetic_Cipher_ui import MonoalphabeticWidget
from .Playfair_ui import PlayfairWidget
from .Vigenere_ui import VigenereWidget

```




### BUG
1.子窗口打开时不能修改标题。


## Version1.2 -2023.12.06

修复：
修复了一些已知的bug：导入bug
Password_system_ui

```
combo_box=[ComboBox(enabled=True, id="ComboBox", label="Select",
                    items=["SHA1", "SHA256", "SHA3-256", "MD5", "SM3"])]
```

```
combo_widget.currentIndexChanged.connect(combo.changed_function)  # 添加这一行以关联信号和槽函数
```

已添加changed_function，操作为pass