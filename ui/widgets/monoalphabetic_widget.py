"""
单表替换密码界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, LineEdit,
    InfoBar, MessageBox, PushButton
)

from ui.components.algorithm_card import EncryptCard, DecryptCard, LogCard, KeyCard
from core.algorithms.classical.Monoalphabetic_Cipher import Thread as MonoThread


class MonoalphabeticWidget(ScrollArea):
    """单表替换密码界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("monoalphabeticWidget")
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
        title = TitleLabel("单表替换密码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "单表替换密码使用一个固定的替换表将明文字母替换为密文字母。"
            "密钥是一个包含字母的字符串，用于生成替换表。"
            "重复字母会被自动去除，剩余字母按字母表顺序填充。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥卡片
        self.keyCard = KeyCard()
        self.keyCard.keyEdit.setPlainText("secret")
        self.keyCard.keyEdit.setPlaceholderText("输入密钥（字母）...")
        self.keyCard.keyEdit.setMaximumHeight(60)
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlainText("Hello World")
        self.encryptCard.plaintextEdit.setPlaceholderText("输入明文...")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        self.decryptCard.ciphertextEdit.setPlaceholderText("输入密文...")
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("单表替换密码已加载", "success")
    
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
        """生成随机密钥"""
        import random
        import string
        
        # 生成随机字母序列
        letters = list(string.ascii_lowercase)
        random.shuffle(letters)
        key = ''.join(letters[:10])  # 取前10个字母
        
        self.keyCard.setKey(key)
        self.logCard.log(f"已生成随机密钥: {key}", "success")
        InfoBar.success(
            title="生成成功",
            content="已生成随机密钥",
            parent=self
        )
    
    def validateKey(self, key):
        """验证密钥"""
        if not key:
            raise ValueError("请输入密钥")
        
        # 只保留字母
        key = ''.join(c for c in key if c.isalpha())
        
        if not key:
            raise ValueError("密钥必须包含字母")
        
        return key.lower()
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 验证密钥
            key_text = self.keyCard.getKey()
            key = self.validateKey(key_text)
            
            # 获取明文
            plaintext = self.encryptCard.getPlaintext()
            if not plaintext:
                raise ValueError("请输入明文")
            
            self.logCard.log(f"明文: {plaintext[:50]}{'...' if len(plaintext) > 50 else ''}", "info")
            self.logCard.log(f"密钥: {key}", "info")
            
            # 创建加密线程
            thread = MonoThread(self, plaintext, key, 0)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, ciphertext):
        """加密完成"""
        self.encryptCard.setCiphertext(ciphertext)
        self.decryptCard.setCiphertext(ciphertext)
        self.logCard.log(f"密文: {ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}", "success")
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
            key = self.validateKey(key_text)
            
            # 获取密文
            ciphertext = self.decryptCard.getCiphertext()
            if not ciphertext:
                raise ValueError("请输入密文")
            
            self.logCard.log(f"密文: {ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}", "info")
            self.logCard.log(f"密钥: {key}", "info")
            
            # 创建解密线程
            thread = MonoThread(self, ciphertext, key, 1)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, plaintext):
        """解密完成"""
        self.decryptCard.setPlaintext(plaintext)
        self.logCard.log(f"明文: {plaintext[:50]}{'...' if len(plaintext) > 50 else ''}", "success")
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
