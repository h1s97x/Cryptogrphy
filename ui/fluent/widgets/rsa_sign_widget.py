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
        title = BodyLabel("✍️ 签名")
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
        from PyQt5.QtWidgets import QHBoxLayout
        btnLayout = QHBoxLayout()
        btnLayout.setSpacing(8)
        
        self.signBtn = PushButton("生成签名")
        btnLayout.addWidget(self.signBtn)
        
        self.copyBtn = PushButton("复制签名")
        btnLayout.addWidget(self.copyBtn)
        
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getMessage(self):
        """获取消息"""
        return self.messageEdit.toPlainText()
    
    def setMessage(self, message):
        """设置消息"""
        self.messageEdit.setPlainText(message)
    
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


class RSAVerifyCard(CardWidget):
    """RSA验证卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("✅ 签名验证")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 消息输入
        msgLabel = BodyLabel("消息:")
        layout.addWidget(msgLabel)
        
        self.messageEdit = PlainTextEdit()
        self.messageEdit.setPlaceholderText("输入要验证的消息...")
        self.messageEdit.setMaximumHeight(80)
        layout.addWidget(self.messageEdit)
        
        # 签名输入
        sigLabel = BodyLabel("签名值:")
        layout.addWidget(sigLabel)
        
        self.signatureEdit = PlainTextEdit()
        self.signatureEdit.setPlaceholderText("输入签名值...")
        self.signatureEdit.setMaximumHeight(80)
        layout.addWidget(self.signatureEdit)
        
        # 验证结果
        resultLabel = BodyLabel("验证结果:")
        layout.addWidget(resultLabel)
        
        self.resultEdit = PlainTextEdit()
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setPlaceholderText("验证结果将显示在这里...")
        self.resultEdit.setMaximumHeight(60)
        layout.addWidget(self.resultEdit)
        
        # 按钮
        from PyQt5.QtWidgets import QHBoxLayout
        btnLayout = QHBoxLayout()
        btnLayout.setSpacing(8)
        
        self.verifyBtn = PushButton("验证签名")
        btnLayout.addWidget(self.verifyBtn)
        
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getMessage(self):
        """获取消息"""
        return self.messageEdit.toPlainText()
    
    def setMessage(self, message):
        """设置消息"""
        self.messageEdit.setPlainText(message)
    
    def getSignature(self):
        """获取签名"""
        return self.signatureEdit.toPlainText()
    
    def setSignature(self, signature):
        """设置签名"""
        self.signatureEdit.setPlainText(signature)
    
    def setResult(self, result):
        """设置结果"""
        self.resultEdit.setPlainText(result)
    
    def clear(self):
        """清空"""
        self.messageEdit.clear()
        self.signatureEdit.clear()
        self.resultEdit.clear()


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
        
        # 验证卡片
        self.verifyCard = RSAVerifyCard()
        layout.addWidget(self.verifyCard)
        
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
        self.verifyCard.verifyBtn.clicked.connect(self.verify)
    
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
        # 自动填充到验证卡片
        self.verifyCard.setMessage(self.signCard.getMessage())
        self.verifyCard.setSignature(signature)
        
        self.logCard.log(f"签名值: {signature[:50]}...", "success")
        self.logCard.log("签名完成", "success")
        
        InfoBar.success(
            title="签名成功",
            content="消息已成功签名",
            parent=self
        )
    
    def verify(self):
        """验证签名"""
        try:
            self.logCard.log("开始验证签名...", "info")
            
            # 检查密钥
            keys = self.keyCard.getKeys()
            if keys[0] is None:
                raise ValueError("请先生成密钥对")
            
            # 获取消息和签名
            message = self.verifyCard.getMessage()
            signature_hex = self.verifyCard.getSignature()
            
            if not message:
                raise ValueError("请输入要验证的消息")
            
            if not signature_hex:
                raise ValueError("请输入签名值")
            
            self.logCard.log(f"消息: {message[:50]}{'...' if len(message) > 50 else ''}", "info")
            self.logCard.log(f"签名: {signature_hex[:50]}...", "info")
            
            # 导入验证所需的库
            from Crypto.Hash import SHA256
            from Crypto.Signature import pkcs1_15
            
            # 计算消息哈希
            h = SHA256.new(message.encode('utf-8'))
            
            # 将十六进制签名转换为字节
            signature_bytes = bytes.fromhex(signature_hex.replace(' ', ''))
            
            # 验证签名
            try:
                pkcs1_15.new(keys[0]).verify(h, signature_bytes)
                result = "✅ 验证成功：签名有效"
                self.logCard.log("签名验证通过", "success")
                InfoBar.success(
                    title="验证成功",
                    content="签名验证通过",
                    parent=self
                )
            except (ValueError, TypeError) as e:
                result = "❌ 验证失败：签名无效"
                self.logCard.log("签名验证失败", "error")
                InfoBar.error(
                    title="验证失败",
                    content="签名验证未通过",
                    parent=self
                )
            
            self.verifyCard.setResult(result)
            
        except Exception as e:
            self.logCard.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
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
