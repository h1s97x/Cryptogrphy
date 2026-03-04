"""
算法界面通用卡片组件
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QWidget
from qfluentwidgets import (
    CardWidget, BodyLabel, CaptionLabel, 
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    FluentIcon as FIF
)


class KeyCard(CardWidget):
    """密钥配置卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔑 密钥配置")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 密钥输入框
        self.keyEdit = TextEdit()
        self.keyEdit.setPlaceholderText("输入密钥...")
        self.keyEdit.setMaximumHeight(100)
        layout.addWidget(self.keyEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.generateBtn = PushButton(FIF.SYNC, "生成密钥")
        self.importBtn = PushButton(FIF.FOLDER, "导入文件")
        
        btnLayout.addWidget(self.generateBtn)
        btnLayout.addWidget(self.importBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getKey(self):
        """获取密钥"""
        return self.keyEdit.toPlainText()
    
    def setKey(self, key):
        """设置密钥"""
        self.keyEdit.setPlainText(key)


class EncryptCard(CardWidget):
    """加密卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("🔒 加密")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 明文输入
        plaintextLabel = BodyLabel("明文")
        layout.addWidget(plaintextLabel)
        
        self.plaintextEdit = TextEdit()
        self.plaintextEdit.setPlaceholderText("输入明文或拖拽文件到此处...")
        self.plaintextEdit.setMaximumHeight(100)
        layout.addWidget(self.plaintextEdit)
        
        # 密文输出
        ciphertextLabel = BodyLabel("密文")
        layout.addWidget(ciphertextLabel)
        
        self.ciphertextEdit = TextEdit()
        self.ciphertextEdit.setPlaceholderText("加密结果将显示在这里")
        self.ciphertextEdit.setReadOnly(True)
        self.ciphertextEdit.setMaximumHeight(100)
        layout.addWidget(self.ciphertextEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.encryptBtn = PrimaryPushButton(FIF.SEND, "加密")
        self.copyBtn = PushButton(FIF.COPY, "复制")
        self.saveBtn = PushButton(FIF.SAVE, "保存")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.encryptBtn)
        btnLayout.addWidget(self.copyBtn)
        btnLayout.addWidget(self.saveBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getPlaintext(self):
        """获取明文"""
        return self.plaintextEdit.toPlainText()
    
    def setPlaintext(self, text):
        """设置明文"""
        self.plaintextEdit.setPlainText(text)
    
    def getCiphertext(self):
        """获取密文"""
        return self.ciphertextEdit.toPlainText()
    
    def setCiphertext(self, text):
        """设置密文"""
        self.ciphertextEdit.setPlainText(text)
    
    def clear(self):
        """清空"""
        self.ciphertextEdit.clear()


class DecryptCard(CardWidget):
    """解密卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("🔓 解密")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 密文输入
        ciphertextLabel = BodyLabel("密文")
        layout.addWidget(ciphertextLabel)
        
        self.ciphertextEdit = TextEdit()
        self.ciphertextEdit.setPlaceholderText("输入密文...")
        self.ciphertextEdit.setMaximumHeight(100)
        layout.addWidget(self.ciphertextEdit)
        
        # 明文输出
        plaintextLabel = BodyLabel("明文")
        layout.addWidget(plaintextLabel)
        
        self.plaintextEdit = TextEdit()
        self.plaintextEdit.setPlaceholderText("解密结果将显示在这里")
        self.plaintextEdit.setReadOnly(True)
        self.plaintextEdit.setMaximumHeight(100)
        layout.addWidget(self.plaintextEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.decryptBtn = PrimaryPushButton(FIF.ACCEPT, "解密")
        self.copyBtn = PushButton(FIF.COPY, "复制")
        self.saveBtn = PushButton(FIF.SAVE, "保存")
        
        btnLayout.addWidget(self.decryptBtn)
        btnLayout.addWidget(self.copyBtn)
        btnLayout.addWidget(self.saveBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getCiphertext(self):
        """获取密文"""
        return self.ciphertextEdit.toPlainText()
    
    def setCiphertext(self, text):
        """设置密文"""
        self.ciphertextEdit.setPlainText(text)
    
    def getPlaintext(self):
        """获取明文"""
        return self.plaintextEdit.toPlainText()
    
    def setPlaintext(self, text):
        """设置明文"""
        self.plaintextEdit.setPlainText(text)
    
    def clear(self):
        """清空"""
        self.plaintextEdit.clear()


class LogCard(CardWidget):
    """日志卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        
        # 标题
        card_title = BodyLabel("📊 日志")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 日志显示区域
        self.logEdit = TextEdit()
        self.logEdit.setReadOnly(True)
        self.logEdit.setMaximumHeight(150)
        layout.addWidget(self.logEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        self.exportBtn = PushButton(FIF.SAVE, "导出")
        
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addWidget(self.exportBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
        
        # 连接信号
        self.clearBtn.clicked.connect(self.clear)
    
    def log(self, message, level='info'):
        """添加日志"""
        icons = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌'
        }
        colors = {
            'info': '#3b82f6',
            'success': '#10b981',
            'warning': '#f59e0b',
            'error': '#ef4444'
        }
        
        icon = icons.get(level, 'ℹ️')
        color = colors.get(level, '#3b82f6')
        
        self.logEdit.append(
            f"{icon} <span style='color: {color};'>{message}</span>"
        )
    
    def clear(self):
        """清空日志"""
        self.logEdit.clear()
