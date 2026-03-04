"""
AES 加密算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel,
    InfoBar, MessageBox
)

from ui.fluent.components.algorithm_card import KeyCard, EncryptCard, DecryptCard, LogCard
from core.algorithms.symmetric.AES import Thread as AESThread
from infrastructure.converters import TypeConvert


class AESWidget(ScrollArea):
    """AES 加密算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("aesWidget")
        self.initUI()
        self.connectSignals()
    
    def initUI(self):
        """初始化UI"""
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(16)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        title = TitleLabel("AES 加密")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "AES (Advanced Encryption Standard) 是一种对称加密算法，"
            "使用128位密钥对128位数据块进行加密。输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥配置卡片
        self.keyCard = KeyCard()
        self.keyCard.keyEdit.setPlainText("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C")
        self.keyCard.keyEdit.setPlaceholderText("输入128位密钥（十六进制）...")
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlainText("32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34")
        self.encryptCard.plaintextEdit.setPlaceholderText("输入128位明文（十六进制）...")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        self.decryptCard.ciphertextEdit.setPlaceholderText("输入128位密文（十六进制）...")
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("AES 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 密钥卡片
        self.keyCard.generateBtn.clicked.connect(self.generateKey)
        
        # 加密卡片
        self.encryptCard.encryptBtn.clicked.connect(self.encrypt)
        self.encryptCard.copyBtn.clicked.connect(self.copyCiphertext)
        self.encryptCard.clearBtn.clicked.connect(self.encryptCard.clear)
        
        # 解密卡片
        self.decryptCard.decryptBtn.clicked.connect(self.decrypt)
        self.decryptCard.copyBtn.clicked.connect(self.copyPlaintext)
    
    def generateKey(self):
        """生成密钥"""
        import os
        key_bytes = os.urandom(16)
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.keyCard.setKey(key_hex)
        self.logCard.log(f"已生成随机密钥", "success")
        InfoBar.success(
            title="生成成功",
            content="已生成128位随机密钥",
            parent=self
        )
    
    def validateHexInput(self, text, name, expected_length=16):
        """验证十六进制输入"""
        try:
            hex_list = TypeConvert.str_to_hex_list(text)
            
            if hex_list == 'ERROR_CHARACTER':
                raise ValueError(f"{name}包含非法字符，只能包含十六进制字符（0-9, A-F）")
            
            if hex_list == 'ERROR_LENGTH':
                raise ValueError(f"{name}长度必须是2的倍数")
            
            if hex_list is None:
                raise ValueError(f"{name}格式错误")
            
            if len(hex_list) != expected_length:
                raise ValueError(f"{name}长度必须是{expected_length}字节（{expected_length*2}个十六进制字符），当前长度为{len(hex_list)}字节")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            
            # 验证明文
            plaintext_text = self.encryptCard.getPlaintext()
            valid, result = self.validateHexInput(plaintext_text, "明文", 16)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            plaintext = TypeConvert.str_to_int(plaintext_text)
            key = TypeConvert.str_to_int(key_text)
            
            # 格式化显示
            plaintext_formatted = TypeConvert.int_to_str(plaintext, 16)
            key_formatted = TypeConvert.int_to_str(key, 16)
            
            self.encryptCard.setPlaintext(plaintext_formatted)
            self.keyCard.setKey(key_formatted)
            
            self.logCard.log(f"明文: {plaintext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建加密线程
            thread = AESThread(self, plaintext, key, 0)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, ciphertext):
        """加密完成"""
        self.encryptCard.setCiphertext(ciphertext)
        self.decryptCard.setCiphertext(ciphertext)
        self.logCard.log(f"密文: {ciphertext}", "success")
        self.logCard.log("加密完成", "success")
        
        InfoBar.success(
            title="加密成功",
            content="明文已成功加密",
            parent=self
        )
    
    def decrypt(self):
        """解密"""
        try:
            self.logCard.log("开始解密...", "info")
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            
            # 验证密文
            ciphertext_text = self.decryptCard.getCiphertext()
            valid, result = self.validateHexInput(ciphertext_text, "密文", 16)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            ciphertext = TypeConvert.str_to_int(ciphertext_text)
            key = TypeConvert.str_to_int(key_text)
            
            # 格式化显示
            ciphertext_formatted = TypeConvert.int_to_str(ciphertext, 16)
            key_formatted = TypeConvert.int_to_str(key, 16)
            
            self.decryptCard.setCiphertext(ciphertext_formatted)
            self.keyCard.setKey(key_formatted)
            
            self.logCard.log(f"密文: {ciphertext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建解密线程
            thread = AESThread(self, ciphertext, key, 1)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, plaintext):
        """解密完成"""
        self.decryptCard.setPlaintext(plaintext)
        self.logCard.log(f"明文: {plaintext}", "success")
        self.logCard.log("解密完成", "success")
        
        InfoBar.success(
            title="解密成功",
            content="密文已成功解密",
            parent=self
        )
    
    def copyCiphertext(self):
        """复制密文"""
        from PyQt5.QtWidgets import QApplication
        ciphertext = self.encryptCard.getCiphertext()
        QApplication.clipboard().setText(ciphertext)
        InfoBar.success(title="已复制", content="密文已复制到剪贴板", parent=self)
        self.logCard.log("密文已复制到剪贴板", "info")
    
    def copyPlaintext(self):
        """复制明文"""
        from PyQt5.QtWidgets import QApplication
        plaintext = self.decryptCard.getPlaintext()
        QApplication.clipboard().setText(plaintext)
        InfoBar.success(title="已复制", content="明文已复制到剪贴板", parent=self)
        self.logCard.log("明文已复制到剪贴板", "info")
