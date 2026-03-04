"""
SPECK 轻量级分组密码界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel,
    InfoBar, MessageBox
)

from ui.components.algorithm_card import KeyCard, EncryptCard, DecryptCard, LogCard
from core.algorithms.symmetric.SPECK import Thread as SPECKThread
from infrastructure.converters import TypeConvert


class SPECKWidget(ScrollArea):
    """SPECK 轻量级分组密码界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("speckWidget")
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
        title = TitleLabel("SPECK 轻量级分组密码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "SPECK 是NSA设计的轻量级分组密码，适用于资源受限环境。"
            "本实现使用128位密钥和128位数据块，32轮加密。"
            "输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥配置卡片
        self.keyCard = KeyCard()
        self.keyCard.keyEdit.setPlainText("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        self.keyCard.keyEdit.setPlaceholderText("输入128位密钥（十六进制）...")
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlainText("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")
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
        self.logCard.log("SPECK 算法已加载", "success")
    
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
    
    def validateHexList(self, text, name, expected_length=16):
        """验证十六进制列表输入"""
        try:
            hex_list = TypeConvert.str_to_hex_list(text)
            
            if hex_list is None or hex_list == 'ERROR_CHARACTER' or hex_list == 'ERROR_LENGTH':
                raise ValueError(f"{name}格式错误")
            
            if len(hex_list) != expected_length:
                raise ValueError(f"{name}长度必须是{expected_length}字节，当前长度为{len(hex_list)}字节")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            valid, result = self.validateHexList(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            key_list = result
            
            # 验证明文
            plaintext_text = self.encryptCard.getPlaintext()
            valid, result = self.validateHexList(plaintext_text, "明文", 16)
            if not valid:
                raise ValueError(result)
            plaintext_list = result
            
            # 转换为整数
            plaintext_int = TypeConvert.hex_list_to_int(plaintext_list)
            key_int = TypeConvert.hex_list_to_int(key_list)
            
            # 格式化显示
            plaintext_formatted = TypeConvert.hex_list_to_str(plaintext_list)
            key_formatted = TypeConvert.hex_list_to_str(key_list)
            
            self.encryptCard.setPlaintext(plaintext_formatted)
            self.keyCard.setKey(key_formatted)
            
            self.logCard.log(f"明文: {plaintext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建加密线程
            thread = SPECKThread(self, plaintext_int, key_int, 0, key_size=128, block_size=128)
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
            valid, result = self.validateHexList(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            key_list = result
            
            # 验证密文
            ciphertext_text = self.decryptCard.getCiphertext()
            valid, result = self.validateHexList(ciphertext_text, "密文", 16)
            if not valid:
                raise ValueError(result)
            ciphertext_list = result
            
            # 转换为整数
            ciphertext_int = TypeConvert.hex_list_to_int(ciphertext_list)
            key_int = TypeConvert.hex_list_to_int(key_list)
            
            # 格式化显示
            ciphertext_formatted = TypeConvert.hex_list_to_str(ciphertext_list)
            key_formatted = TypeConvert.hex_list_to_str(key_list)
            
            self.decryptCard.setCiphertext(ciphertext_formatted)
            self.keyCard.setKey(key_formatted)
            
            self.logCard.log(f"密文: {ciphertext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建解密线程
            thread = SPECKThread(self, ciphertext_int, key_int, 1, key_size=128, block_size=128)
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
