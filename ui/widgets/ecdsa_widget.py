"""
ECDSA 数字签名算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, TextEdit, PrimaryPushButton,
    FluentIcon as FIF
)

from ui.components.algorithm_card import LogCard
from core.algorithms.asymmetric import ECDSA


class ECDSAKeyCard(CardWidget):
    """ECDSA密钥卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔑 ECDSA 密钥对 (NIST P-256)")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 私钥
        self.privateKeyEdit = TextEdit()
        self.privateKeyEdit.setPlaceholderText("私钥 (d)")
        self.privateKeyEdit.setReadOnly(True)
        self.privateKeyEdit.setMaximumHeight(60)
        layout.addWidget(BodyLabel("私钥 (d)"))
        layout.addWidget(self.privateKeyEdit)
        
        # 公钥
        self.publicKeyEdit = TextEdit()
        self.publicKeyEdit.setPlaceholderText("公钥 (x, y)")
        self.publicKeyEdit.setReadOnly(True)
        self.publicKeyEdit.setMaximumHeight(80)
        layout.addWidget(BodyLabel("公钥 (x, y)"))
        layout.addWidget(self.publicKeyEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.generateBtn = PrimaryPushButton(FIF.SYNC, "生成密钥对")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.generateBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def setKey(self, private_key, public_key):
        """设置密钥"""
        self.privateKeyEdit.setPlainText(private_key)
        self.publicKeyEdit.setPlainText(public_key)
    
    def clear(self):
        """清空"""
        self.privateKeyEdit.clear()
        self.publicKeyEdit.clear()


class ECDSASignCard(CardWidget):
    """ECDSA签名卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("✍️ 数字签名")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 消息输入
        messageLabel = BodyLabel("消息")
        layout.addWidget(messageLabel)
        
        self.messageEdit = TextEdit()
        self.messageEdit.setPlaceholderText("输入要签名的消息...")
        self.messageEdit.setMaximumHeight(100)
        layout.addWidget(self.messageEdit)
        
        # 签名输出
        signatureLabel = BodyLabel("签名值")
        layout.addWidget(signatureLabel)
        
        self.signatureEdit = TextEdit()
        self.signatureEdit.setPlaceholderText("签名结果将显示在这里")
        self.signatureEdit.setReadOnly(True)
        self.signatureEdit.setMaximumHeight(80)
        layout.addWidget(self.signatureEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.signBtn = PrimaryPushButton(FIF.EDIT, "签名")
        self.copyBtn = PushButton(FIF.COPY, "复制签名")
        
        btnLayout.addWidget(self.signBtn)
        btnLayout.addWidget(self.copyBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getMessage(self):
        """获取消息"""
        return self.messageEdit.toPlainText()
    
    def setMessage(self, text):
        """设置消息"""
        self.messageEdit.setPlainText(text)
    
    def getSignature(self):
        """获取签名"""
        return self.signatureEdit.toPlainText()
    
    def setSignature(self, text):
        """设置签名"""
        self.signatureEdit.setPlainText(text)


class ECDSAVerifyCard(CardWidget):
    """ECDSA验证卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("✅ 签名验证")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 消息输入
        messageLabel = BodyLabel("消息")
        layout.addWidget(messageLabel)
        
        self.messageEdit = TextEdit()
        self.messageEdit.setPlaceholderText("输入要验证的消息...")
        self.messageEdit.setMaximumHeight(80)
        layout.addWidget(self.messageEdit)
        
        # 签名输入
        signatureLabel = BodyLabel("签名值")
        layout.addWidget(signatureLabel)
        
        self.signatureEdit = TextEdit()
        self.signatureEdit.setPlaceholderText("输入签名值...")
        self.signatureEdit.setMaximumHeight(80)
        layout.addWidget(self.signatureEdit)
        
        # 验证结果
        resultLabel = BodyLabel("验证结果")
        layout.addWidget(resultLabel)
        
        self.resultEdit = TextEdit()
        self.resultEdit.setPlaceholderText("验证结果将显示在这里")
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setMaximumHeight(60)
        layout.addWidget(self.resultEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.verifyBtn = PrimaryPushButton(FIF.ACCEPT, "验证")
        
        btnLayout.addWidget(self.verifyBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getMessage(self):
        """获取消息"""
        return self.messageEdit.toPlainText()
    
    def setMessage(self, text):
        """设置消息"""
        self.messageEdit.setPlainText(text)
    
    def getSignature(self):
        """获取签名"""
        return self.signatureEdit.toPlainText()
    
    def setSignature(self, text):
        """设置签名"""
        self.signatureEdit.setPlainText(text)
    
    def setResult(self, text):
        """设置结果"""
        self.resultEdit.setPlainText(text)


class ECDSAWidget(ScrollArea):
    """ECDSA 数字签名算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ecdsaWidget")
        self.key = None
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
        title = TitleLabel("ECDSA 数字签名")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "ECDSA (Elliptic Curve Digital Signature Algorithm) 是基于椭圆曲线的数字签名算法。"
            "使用 NIST P-256 曲线，结合 SHA-256 哈希函数进行签名和验证。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥卡片
        self.keyCard = ECDSAKeyCard()
        layout.addWidget(self.keyCard)
        
        # 签名卡片
        self.signCard = ECDSASignCard()
        self.signCard.setMessage("Hello, ECDSA!")
        layout.addWidget(self.signCard)
        
        # 验证卡片
        self.verifyCard = ECDSAVerifyCard()
        layout.addWidget(self.verifyCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("ECDSA 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 密钥卡片
        self.keyCard.generateBtn.clicked.connect(self.generateKey)
        self.keyCard.clearBtn.clicked.connect(self.clearKey)
        
        # 签名卡片
        self.signCard.signBtn.clicked.connect(self.sign)
        self.signCard.copyBtn.clicked.connect(self.copySignature)
        
        # 验证卡片
        self.verifyCard.verifyBtn.clicked.connect(self.verify)
    
    def generateKey(self):
        """生成密钥对"""
        try:
            self.logCard.log("正在生成ECDSA密钥对...", "info")
            
            thread = ECDSA.ECDSAKeyThread(self)
            thread.call_back.connect(self.onKeyGenerated)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"生成密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成密钥失败: {str(e)}", self).exec()
    
    def onKeyGenerated(self, private_key, public_key, key):
        """密钥生成完成"""
        self.key = key
        self.keyCard.setKey(private_key, public_key)
        
        self.logCard.log("密钥对生成完成", "success")
        self.logCard.log(f"私钥: {private_key[:50]}...", "info")
        self.logCard.log(f"公钥: {public_key[:50]}...", "info")
        
        InfoBar.success(
            title="生成成功",
            content="ECDSA密钥对已生成",
            parent=self
        )
    
    def clearKey(self):
        """清空密钥"""
        self.keyCard.clear()
        self.key = None
        self.logCard.log("密钥已清空", "info")
    
    def sign(self):
        """签名"""
        try:
            self.logCard.log("开始签名...", "info")
            
            # 检查密钥
            if self.key is None:
                raise ValueError("请先生成密钥对")
            
            # 获取消息
            message = self.signCard.getMessage()
            if not message:
                raise ValueError("请输入要签名的消息")
            
            message_bytes = message.encode('utf-8')
            
            self.logCard.log(f"消息: {message}", "info")
            self.logCard.log(f"使用私钥签名", "info")
            
            # 创建签名线程
            thread = ECDSA.ECDSASignatureThread(self, message_bytes, self.key)
            thread.call_back.connect(self.onSignFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"签名失败: {str(e)}", "error")
            MessageBox("错误", f"签名失败: {str(e)}", self).exec()
    
    def onSignFinished(self, signature):
        """签名完成"""
        self.signCard.setSignature(signature)
        self.verifyCard.setSignature(signature)
        self.verifyCard.setMessage(self.signCard.getMessage())
        
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
            if self.key is None:
                raise ValueError("请先生成密钥对")
            
            # 获取消息和签名
            message = self.verifyCard.getMessage()
            signature_hex = self.verifyCard.getSignature()
            
            if not message:
                raise ValueError("请输入要验证的消息")
            
            if not signature_hex:
                raise ValueError("请输入签名值")
            
            message_bytes = message.encode('utf-8')
            signature_bytes = bytes.fromhex(signature_hex.replace(' ', ''))
            
            self.logCard.log(f"消息: {message}", "info")
            self.logCard.log(f"签名: {signature_hex[:50]}...", "info")
            self.logCard.log(f"使用公钥验证", "info")
            
            # 创建验证线程
            thread = ECDSA.VerifySignatureThread(self, message_bytes, signature_bytes, self.key)
            thread.call_back.connect(self.onVerifyFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    def onVerifyFinished(self, result):
        """验证完成"""
        self.verifyCard.setResult(result)
        
        if "Success" in result:
            self.logCard.log(f"验证结果: {result}", "success")
            InfoBar.success(
                title="验证成功",
                content="签名验证通过",
                parent=self
            )
        else:
            self.logCard.log(f"验证结果: {result}", "error")
            InfoBar.error(
                title="验证失败",
                content="签名验证未通过",
                parent=self
            )
    
    def copySignature(self):
        """复制签名"""
        from PyQt5.QtWidgets import QApplication
        signature = self.signCard.getSignature()
        if signature:
            QApplication.clipboard().setText(signature)
            InfoBar.success(title="已复制", content="签名已复制到剪贴板", parent=self)
            self.logCard.log("签名已复制到剪贴板", "info")
        else:
            InfoBar.warning(title="提示", content="没有可复制的签名", parent=self)
