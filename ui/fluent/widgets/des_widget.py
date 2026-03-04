"""
DES 加密算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, ComboBox, PrimaryPushButton,
    FluentIcon as FIF
)

from ui.fluent.components.algorithm_card import EncryptCard, DecryptCard, LogCard, KeyCard
from core.algorithms.symmetric.DES import Thread as DESThread
from infrastructure.converters import TypeConvert


class DESWidget(ScrollArea):
    """DES 加密算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("desWidget")
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
        title = TitleLabel("DES 加密")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "DES (Data Encryption Standard) 是一种对称加密算法，"
            "使用56位密钥对64位数据块进行加密。支持DES和3-DES模式。输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 模式选择卡片
        modeCard = CardWidget()
        modeLayout = QVBoxLayout(modeCard)
        modeLayout.setSpacing(12)
        
        modeTitle = BodyLabel("⚙️ 加密模式")
        modeTitle.setStyleSheet("font-weight: bold; font-size: 14px;")
        modeLayout.addWidget(modeTitle)
        
        self.modeComboBox = ComboBox()
        self.modeComboBox.addItems(["DES", "3-DES"])
        self.modeComboBox.setCurrentIndex(0)
        modeLayout.addWidget(self.modeComboBox)
        
        layout.addWidget(modeCard)
        
        # 密钥配置卡片
        self.keyCard = KeyCard()
        self.keyCard.keyEdit.setPlainText("0F 15 71 C9 47 D9 E8 59")
        self.keyCard.keyEdit.setPlaceholderText("输入密钥（十六进制）...")
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlainText("02 46 8A CE EC A8 64 20")
        self.encryptCard.plaintextEdit.setPlaceholderText("输入64位明文（十六进制）...")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        self.decryptCard.ciphertextEdit.setPlaceholderText("输入64位密文（十六进制）...")
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("DES 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 模式切换
        self.modeComboBox.currentIndexChanged.connect(self.onModeChanged)
        
        # 密钥卡片
        self.keyCard.generateBtn.clicked.connect(self.generateKey)
        
        # 加密卡片
        self.encryptCard.encryptBtn.clicked.connect(self.encrypt)
        self.encryptCard.copyBtn.clicked.connect(self.copyCiphertext)
        self.encryptCard.clearBtn.clicked.connect(self.encryptCard.clear)
        
        # 解密卡片
        self.decryptCard.decryptBtn.clicked.connect(self.decrypt)
        self.decryptCard.copyBtn.clicked.connect(self.copyPlaintext)
    
    def onModeChanged(self, index):
        """模式切换"""
        if index == 0:  # DES
            self.keyCard.setKey("0F 15 71 C9 47 D9 E8 59")
            self.logCard.log("切换到 DES 模式（8字节密钥）", "info")
        else:  # 3-DES
            self.keyCard.setKey("0F 15 71 C9 47 D9 E8 59 0F 15 71 C9 47 D9 E8 59 0F 15 71 C9 47 D9 E8 59")
            self.logCard.log("切换到 3-DES 模式（24字节密钥）", "info")
    
    def generateKey(self):
        """生成密钥"""
        import os
        mode = self.modeComboBox.currentIndex()
        
        if mode == 0:  # DES
            key_bytes = os.urandom(8)
        else:  # 3-DES
            key_bytes = os.urandom(24)
        
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.keyCard.setKey(key_hex)
        
        mode_name = "DES" if mode == 0 else "3-DES"
        self.logCard.log(f"已生成 {mode_name} 随机密钥", "success")
        InfoBar.success(
            title="生成成功",
            content=f"已生成{mode_name}随机密钥",
            parent=self
        )
    
    def validateHexInput(self, text, name, expected_length):
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
                raise ValueError(f"{name}长度必须是{expected_length}字节，当前长度为{len(hex_list)}字节")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            mode = self.modeComboBox.currentIndex()
            key_len = 8 if mode == 0 else 24
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", key_len)
            if not valid:
                raise ValueError(result)
            
            # 验证明文
            plaintext_text = self.encryptCard.getPlaintext()
            valid, result = self.validateHexInput(plaintext_text, "明文", 8)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            plaintext = TypeConvert.str_to_int(plaintext_text)
            key = TypeConvert.str_to_int(key_text)
            
            # 格式化显示
            plaintext_formatted = TypeConvert.int_to_str(plaintext, 8)
            key_formatted = TypeConvert.int_to_str(key, key_len)
            
            self.encryptCard.setPlaintext(plaintext_formatted)
            self.keyCard.setKey(key_formatted)
            
            mode_name = "DES" if mode == 0 else "3-DES"
            self.logCard.log(f"模式: {mode_name}", "info")
            self.logCard.log(f"明文: {plaintext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建加密线程
            thread = DESThread(self, plaintext, 8, key, key_len, 0, mode)
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
            
            mode = self.modeComboBox.currentIndex()
            key_len = 8 if mode == 0 else 24
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", key_len)
            if not valid:
                raise ValueError(result)
            
            # 验证密文
            ciphertext_text = self.decryptCard.getCiphertext()
            valid, result = self.validateHexInput(ciphertext_text, "密文", 8)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            ciphertext = TypeConvert.str_to_int(ciphertext_text)
            key = TypeConvert.str_to_int(key_text)
            
            # 格式化显示
            ciphertext_formatted = TypeConvert.int_to_str(ciphertext, 8)
            key_formatted = TypeConvert.int_to_str(key, key_len)
            
            self.decryptCard.setCiphertext(ciphertext_formatted)
            self.keyCard.setKey(key_formatted)
            
            mode_name = "DES" if mode == 0 else "3-DES"
            self.logCard.log(f"模式: {mode_name}", "info")
            self.logCard.log(f"密文: {ciphertext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建解密线程
            thread = DESThread(self, ciphertext, 8, key, key_len, 1, mode)
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
