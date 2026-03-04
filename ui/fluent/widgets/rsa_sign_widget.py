"""
RSA 数字签名界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, PlainTextEdit,
    PushButton, InfoBar, MessageBox, CardWidget
)

from ui.fluent.components.algorithm_card import LogCard
from core.algorithms.asymmetric.RSA_Sign import KeyThread, RsaSignThread


class RSASignKeyCard(CardWidget):
    """RSA签名密钥卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.public_key = None
        self.private_key = None
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("密钥对")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 公钥显示
        pubLabel = BodyLabel("公钥 (用于验证):")
        layout.addWidget(pubLabel)
        
        self.publicKeyEdit = PlainTextEdit()
        self.publicKeyEdit.setReadOnly(True)
        self.publicKeyEdit.setPlaceholderText("点击生成密钥对...")
        self.publicKeyEdit.setMaximumHeight(100)
        layout.addWidget(self.publicKeyEdit)
        
        # 私钥显示
        privLabel = BodyLabel("私钥 (用于签名):")
        layout.addWidget(privLabel)
        
        self.privateKeyEdit = PlainTextEdit()
        self.privateKeyEdit.setReadOnly(True)
        self.privateKeyEdit.setPlaceholderText("点击生成密钥对...")
        self.privateKeyEdit.setMaximumHeight(100)
        layout.addWidget(self.privateKeyEdit)
        
        # 生成按钮
        self.generateBtn = PushButton("生成密钥对")
        layout.addWidget(self.generateBtn)
    
    def setKeys(self, public_key, private_key):
        """设置密钥对"""
        self.public_key = public_key
        self.private_key = private_key
        
        if public_key:
            pub_pem = public_key.export_key().decode('utf-8')
            self.publicKeyEdit.setPlainText(pub_pem)
        
        if private_key:
            priv_pem = private_key.export_key().decode('utf-8')
            self.privateKeyEdit.setPlainText(priv_pem)
    
    def getKeys(self):
        """获取密钥对"""
        return (self.public_key, self.private_key)


class RSASignCard(CardWidget):
    """RSA签名卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("签名")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 消息输入
        msgLabel = BodyLabel("消息:")
        layout.addWidget(msgLabel)
        
        self.messageEdit = PlainTextEdit()
        self.messageEdit.setPlaceholderText("输入要签名的消息...")
        self.messageEdit.setMaximumHeight(100)
        layout.addWidget(self.messageEdit)
        
        # 签名输出
        sigLabel = BodyLabel("签名值:")
        layout.addWidget(sigLabel)
        
        self.signatureEdit = PlainTextEdit()
        self.signatureEdit.setReadOnly(True)
        self.signatureEdit.setPlaceholderText("签名结果将显示在这里...")
        self.signatureEdit.setMaximumHeight(100)
        layout.addWidget(self.signatureEdit)
        
        # 按钮
        btnLayout = QVBoxLayout()
        btnLayout.setSpacing(8)
        
        self.signBtn = PushButton("生成签名")
        btnLayout.addWidget(self.signBtn)
        
        self.copyBtn = PushButton("复制签名")
        btnLayout.addWidget(self.copyBtn)
        
        layout.addLayout(btnLayout)
    
    def getMessage(self):
        """获取消息"""
        return self.messageEdit.toPlainText()
    
    def setSignature(self, signature):
        """设置签名"""
        self.signatureEdit.setPlainText(signature)
    
    def getSignature(self):
        """获取签名"""
        return self.signatureEdit.toPlainText()
    
    def clear(self):
        """清空"""
        self.messageEdit.clear()
        self.signatureEdit.clear()


class RSASignWidget(ScrollArea):
    """RSA 数字签名界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("rsaSignWidget")
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
        title = TitleLabel("RSA 数字签名")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "RSA 数字签名使用私钥对消息的哈希值进行签名，"
            "接收方可以使用公钥验证签名的真实性。本实现使用1024位密钥和SHA-256哈希。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥卡片
        self.keyCard = RSASignKeyCard()
        layout.addWidget(self.keyCard)
        
        # 签名卡片
        self.signCard = RSASignCard()
        layout.addWidget(self.signCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("RSA 数字签名已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.keyCard.generateBtn.clicked.connect(self.generateKeys)
        self.signCard.signBtn.clicked.connect(self.sign)
        self.signCard.copyBtn.clicked.connect(self.copySignature)
    
    def generateKeys(self):
        """生成密钥对"""
        try:
            self.logCard.log("正在生成密钥对...", "info")
            
            # 创建密钥生成线程
            thread = KeyThread(self)
            thread.call_back.connect(self.onKeysGenerated)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"密钥生成失败: {str(e)}", "error")
            MessageBox("错误", f"密钥生成失败: {str(e)}", self).exec()
    
    def onKeysGenerated(self, keys):
        """密钥生成完成"""
        public_key, private_key = keys
        
        if public_key is None or private_key is None:
            self.logCard.log("密钥生成失败", "error")
            MessageBox("错误", "密钥生成失败", self).exec()
            return
        
        self.keyCard.setKeys(public_key, private_key)
        self.logCard.log("密钥对生成成功", "success")
        
        InfoBar.success(
            title="生成成功",
            content="RSA 密钥对已生成",
            parent=self
        )
    
    def sign(self):
        """生成签名"""
        try:
            self.logCard.log("开始签名...", "info")
            
            # 检查密钥
            keys = self.keyCard.getKeys()
            if keys[0] is None or keys[1] is None:
                raise ValueError("请先生成密钥对")
            
            # 获取消息
            message = self.signCard.getMessage()
            if not message:
                raise ValueError("请输入要签名的消息")
            
            self.logCard.log(f"消息: {message[:50]}{'...' if len(message) > 50 else ''}", "info")
            
            # 创建签名线程
            thread = RsaSignThread(self, message, keys)
            thread.call_back.connect(self.onSignFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"签名失败: {str(e)}", "error")
            MessageBox("错误", f"签名失败: {str(e)}", self).exec()
    
    def onSignFinished(self, signature):
        """签名完成"""
        if signature == "Sign Failed":
            self.logCard.log("签名失败", "error")
            MessageBox("错误", "签名失败", self).exec()
            return
        
        self.signCard.setSignature(signature)
        self.logCard.log(f"签名值: {signature[:50]}...", "success")
        self.logCard.log("签名完成", "success")
        
        InfoBar.success(
            title="签名成功",
            content="消息已成功签名",
            parent=self
        )
    
    def copySignature(self):
        """复制签名"""
        from PyQt5.QtWidgets import QApplication
        signature = self.signCard.getSignature()
        if not signature:
            InfoBar.warning(title="提示", content="没有可复制的签名", parent=self)
            return
        
        QApplication.clipboard().setText(signature)
        InfoBar.success(title="已复制", content="签名已复制到剪贴板", parent=self)
        self.logCard.log("签名已复制到剪贴板", "info")
