"""
RC4 流密码界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel,
    InfoBar, MessageBox
)

from ui.fluent.components.algorithm_card import KeyCard, EncryptCard, DecryptCard, LogCard
from core.algorithms.symmetric.RC4 import Thread as RC4Thread
from infrastructure.converters import TypeConvert


class RC4Widget(ScrollArea):
    """RC4 流密码界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("rc4Widget")
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
        title = TitleLabel("RC4 流密码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "RC4 是一种流密码算法，使用可变长度密钥（40-2048位）。"
            "通过密钥调度算法(KSA)和伪随机生成算法(PRGA)生成密钥流，"
            "然后与明文进行异或运算。输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥配置卡片
        self.keyCard = KeyCard()
        self.keyCard.keyEdit.setPlainText("01 23 45 67 89 AB CD EF")
        self.keyCard.keyEdit.setPlaceholderText("输入密钥（十六进制，可变长度）...")
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlainText("48 65 6C 6C 6F 20 57 6F 72 6C 64")
        self.encryptCard.plaintextEdit.setPlaceholderText("输入明文（十六进制）...")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        self.decryptCard.ciphertextEdit.setPlaceholderText("输入密文（十六进制）...")
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("RC4 算法已加载", "success")
    
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
        # 生成8字节（64位）密钥
        key_bytes = os.urandom(8)
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.keyCard.setKey(key_hex)
        self.logCard.log(f"已生成随机密钥", "success")
        InfoBar.success(
            title="生成成功",
            content="已生成64位随机密钥",
            parent=self
        )
    
    def validateHexInput(self, text, name):
        """验证十六进制输入"""
        try:
            hex_list = TypeConvert.str_to_hex_list(text)
            
            if hex_list is None or hex_list == 'ERROR_CHARACTER' or hex_list == 'ERROR_LENGTH':
                raise ValueError(f"{name}格式错误")
            
            if len(hex_list) == 0:
                raise ValueError(f"{name}不能为空")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥")
            if not valid:
                raise ValueError(result)
            key_list = result
            key_len = len(key_list)
            
            # 验证明文
            plaintext_text = self.encryptCard.getPlaintext()
            valid, result = self.validateHexInput(plaintext_text, "明文")
            if not valid:
                raise ValueError(result)
            plaintext_list = result
            plaintext_len = len(plaintext_list)
            
            # 转换为整数
            plaintext_int = TypeConvert.hex_list_to_int(plaintext_list)
            key_int = TypeConvert.hex_list_to_int(key_list)
            
            # 格式化显示
            plaintext_formatted = TypeConvert.hex_list_to_str(plaintext_list)
            key_formatted = TypeConvert.hex_list_to_str(key_list)
            
            self.encryptCard.setPlaintext(plaintext_formatted)
            self.keyCard.setKey(key_formatted)
            
            self.logCard.log(f"明文长度: {plaintext_len} 字节", "info")
            self.logCard.log(f"密钥长度: {key_len} 字节", "info")
            
            # 创建加密线程
            thread = RC4Thread(self, plaintext_int, plaintext_len, key_int, key_len, 0)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, ciphertext):
        """加密完成"""
        self.encryptCard.setCiphertext(ciphertext)
        self.decryptCard.setCiphertext(ciphertext)
        self.logCard.log(f"密文: {ciphertext[:50]}...", "success")
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
            valid, result = self.validateHexInput(key_text, "密钥")
            if not valid:
                raise ValueError(result)
            key_list = result
            key_len = len(key_list)
            
            # 验证密文
            ciphertext_text = self.decryptCard.getCiphertext()
            valid, result = self.validateHexInput(ciphertext_text, "密文")
            if not valid:
                raise ValueError(result)
            ciphertext_list = result
            ciphertext_len = len(ciphertext_list)
            
            # 转换为整数
            ciphertext_int = TypeConvert.hex_list_to_int(ciphertext_list)
            key_int = TypeConvert.hex_list_to_int(key_list)
            
            # 格式化显示
            ciphertext_formatted = TypeConvert.hex_list_to_str(ciphertext_list)
            key_formatted = TypeConvert.hex_list_to_str(key_list)
            
            self.decryptCard.setCiphertext(ciphertext_formatted)
            self.keyCard.setKey(key_formatted)
            
            self.logCard.log(f"密文长度: {ciphertext_len} 字节", "info")
            self.logCard.log(f"密钥长度: {key_len} 字节", "info")
            
            # 创建解密线程
            thread = RC4Thread(self, ciphertext_int, ciphertext_len, key_int, key_len, 1)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, plaintext):
        """解密完成"""
        self.decryptCard.setPlaintext(plaintext)
        self.logCard.log(f"明文: {plaintext[:50]}...", "success")
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
