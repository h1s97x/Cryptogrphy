"""
SIMON 轻量级分组密码算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, TextEdit, PrimaryPushButton,
    ComboBox, FluentIcon as FIF
)

from ui.components.algorithm_card import EncryptCard, DecryptCard, LogCard
from core.algorithms.symmetric.SIMON import Thread as SIMONThread
from infrastructure.converters import TypeConvert


class SIMONConfigCard(CardWidget):
    """SIMON配置卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("⚙️ SIMON 配置")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 分组大小
        blockLabel = BodyLabel("分组大小 (bits)")
        layout.addWidget(blockLabel)
        
        self.blockCombo = ComboBox()
        self.blockCombo.addItems(["32", "48", "64", "96", "128"])
        self.blockCombo.setCurrentIndex(2)  # 默认64位
        layout.addWidget(self.blockCombo)
        
        # 密钥大小
        keyLabel = BodyLabel("密钥大小 (bits)")
        layout.addWidget(keyLabel)
        
        self.keyCombo = ComboBox()
        self.keyCombo.addItems(["96", "128"])
        self.keyCombo.setCurrentIndex(0)  # 默认96位
        layout.addWidget(self.keyCombo)
        
        # 密钥输入
        keyInputLabel = BodyLabel("密钥")
        layout.addWidget(keyInputLabel)
        
        self.keyEdit = TextEdit()
        self.keyEdit.setPlaceholderText("输入密钥（十六进制）...")
        self.keyEdit.setMaximumHeight(60)
        layout.addWidget(self.keyEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.generateBtn = PushButton(FIF.SYNC, "生成密钥")
        
        btnLayout.addWidget(self.generateBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getBlockSize(self):
        """获取分组大小"""
        return int(self.blockCombo.currentText())
    
    def getKeySize(self):
        """获取密钥大小"""
        return int(self.keyCombo.currentText())
    
    def getKey(self):
        """获取密钥"""
        return self.keyEdit.toPlainText()
    
    def setKey(self, key):
        """设置密钥"""
        self.keyEdit.setPlainText(key)


class SIMONWidget(ScrollArea):
    """SIMON 轻量级分组密码算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("simonWidget")
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
        title = TitleLabel("SIMON 轻量级密码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "SIMON 是 NSA 设计的轻量级分组密码算法，适用于资源受限环境。"
            "支持多种分组大小（32/48/64/96/128位）和密钥大小（96/128位）。"
            "默认使用 ECB 模式，输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 配置卡片
        self.configCard = SIMONConfigCard()
        # 设置默认密钥 (96位 = 12字节)
        self.configCard.setKey("11 22 33 44 55 66 77 88 99 AA BB CC")
        layout.addWidget(self.configCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        # 设置默认明文 (64位 = 8字节)
        self.encryptCard.plaintextEdit.setPlainText("11 22 33 44 55 66 77 88")
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
        self.logCard.log("SIMON 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 配置卡片
        self.configCard.generateBtn.clicked.connect(self.generateKey)
        
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
        key_size = self.configCard.getKeySize()
        key_bytes = os.urandom(key_size // 8)
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.configCard.setKey(key_hex)
        self.logCard.log(f"已生成{key_size}位随机密钥", "success")
        InfoBar.success(
            title="生成成功",
            content=f"已生成{key_size}位随机密钥",
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
            
            block_size = self.configCard.getBlockSize()
            key_size = self.configCard.getKeySize()
            
            # 验证密钥
            key_text = self.configCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", key_size // 8)
            if not valid:
                raise ValueError(result)
            
            # 验证明文
            plaintext_text = self.encryptCard.getPlaintext()
            valid, result = self.validateHexInput(plaintext_text, "明文", block_size // 8)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            plaintext = TypeConvert.str_to_int(plaintext_text)
            key = TypeConvert.str_to_int(key_text)
            
            # 格式化显示
            plaintext_formatted = TypeConvert.int_to_str(plaintext, block_size // 8)
            key_formatted = TypeConvert.int_to_str(key, key_size // 8)
            
            self.encryptCard.setPlaintext(plaintext_formatted)
            self.configCard.setKey(key_formatted)
            
            self.logCard.log(f"分组大小: {block_size} bits", "info")
            self.logCard.log(f"密钥大小: {key_size} bits", "info")
            self.logCard.log(f"明文: {plaintext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建加密线程
            thread = SIMONThread(self, plaintext, key, 0, key_size, block_size)
            thread.intermediate_value.connect(self.onIntermediateValue)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def decrypt(self):
        """解密"""
        try:
            self.logCard.log("开始解密...", "info")
            
            block_size = self.configCard.getBlockSize()
            key_size = self.configCard.getKeySize()
            
            # 验证密钥
            key_text = self.configCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", key_size // 8)
            if not valid:
                raise ValueError(result)
            
            # 验证密文
            ciphertext_text = self.decryptCard.getCiphertext()
            valid, result = self.validateHexInput(ciphertext_text, "密文", block_size // 8)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            ciphertext = TypeConvert.str_to_int(ciphertext_text)
            key = TypeConvert.str_to_int(key_text)
            
            # 格式化显示
            ciphertext_formatted = TypeConvert.int_to_str(ciphertext, block_size // 8)
            key_formatted = TypeConvert.int_to_str(key, key_size // 8)
            
            self.decryptCard.setCiphertext(ciphertext_formatted)
            self.configCard.setKey(key_formatted)
            
            self.logCard.log(f"分组大小: {block_size} bits", "info")
            self.logCard.log(f"密钥大小: {key_size} bits", "info")
            self.logCard.log(f"密文: {ciphertext_formatted}", "info")
            self.logCard.log(f"密钥: {key_formatted}", "info")
            
            # 创建解密线程
            thread = SIMONThread(self, ciphertext, key, 1, key_size, block_size)
            thread.intermediate_value.connect(self.onIntermediateValue)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onIntermediateValue(self, text):
        """中间值输出"""
        self.logCard.log(text, "info")
    
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
