"""
重放攻击演示 - Fluent Design 版本

演示场景：
1. Alice 使用 ECDSA 对消息签名
2. 攻击者截获消息和签名
3. 攻击者尝试重放（replay）这个签名
4. Bob 验证签名的有效性
"""

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    InfoBar, MessageBox, FluentIcon as FIF
)

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from infrastructure.converters import TypeConvert


def str_add_space(out_str: str) -> str:
    """每2个字符添加一个空格"""
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str.strip()


class SignThread(QThread):
    """签名线程"""
    finished = pyqtSignal(str)
    
    def __init__(self, message, key):
        super().__init__()
        self.message = message
        self.key = key
    
    def run(self):
        try:
            h = SHA256.new(self.message)
            signer = DSS.new(self.key, 'fips-186-3')
            signature = signer.sign(h)
            sig_hex = signature.hex().upper()
            sig_formatted = str_add_space(sig_hex)
            self.finished.emit(sig_formatted)
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}")


class VerifyThread(QThread):
    """验证线程"""
    finished = pyqtSignal(str)
    
    def __init__(self, message, signature, key):
        super().__init__()
        self.message = message
        self.signature = signature
        self.key = key
    
    def run(self):
        try:
            h = SHA256.new(self.message)
            verifier = DSS.new(self.key, 'fips-186-3')
            verifier.verify(h, self.signature)
            self.finished.emit("✅ 验证成功 - 签名有效")
        except ValueError:
            self.finished.emit("❌ 验证失败 - 签名无效")
        except Exception as e:
            self.finished.emit(f"❌ 错误: {str(e)}")


class ReplayAttackWidget(ScrollArea):
    """重放攻击演示界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("replayAttackWidget")
        self.key = None
        self.initUI()
    
    def initUI(self):
        """初始化UI"""
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(16)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        title = TitleLabel("重放攻击演示")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "演示场景：攻击者截获 Alice 的消息和签名，尝试重放给 Bob。\n"
            "使用 ECDSA (P-256) 进行数字签名。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 1. 密钥生成卡片
        self.keyCard = self.createKeyCard()
        layout.addWidget(self.keyCard)
        
        # 2. Alice 签名卡片
        self.aliceCard = self.createAliceCard()
        layout.addWidget(self.aliceCard)
        
        # 3. 攻击者卡片
        self.attackerCard = self.createAttackerCard()
        layout.addWidget(self.attackerCard)
        
        # 4. Bob 验证卡片
        self.bobCard = self.createBobCard()
        layout.addWidget(self.bobCard)
        
        # 5. 日志卡片
        self.logCard = self.createLogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        self.log("重放攻击演示已加载", "success")
    
    def createKeyCard(self):
        """创建密钥生成卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔑 步骤1：生成密钥对")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 私钥
        privLabel = BodyLabel("私钥 (Private Key)")
        layout.addWidget(privLabel)
        self.privateKeyEdit = TextEdit()
        self.privateKeyEdit.setReadOnly(True)
        self.privateKeyEdit.setMaximumHeight(60)
        self.privateKeyEdit.setPlaceholderText("点击生成密钥...")
        layout.addWidget(self.privateKeyEdit)
        
        # 公钥
        pubLabel = BodyLabel("公钥 (Public Key)")
        layout.addWidget(pubLabel)
        self.publicKeyEdit = TextEdit()
        self.publicKeyEdit.setReadOnly(True)
        self.publicKeyEdit.setMaximumHeight(60)
        self.publicKeyEdit.setPlaceholderText("点击生成密钥...")
        layout.addWidget(self.publicKeyEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.genKeyBtn = PrimaryPushButton(FIF.FINGERPRINT, "生成密钥")
        self.genKeyBtn.clicked.connect(self.generateKey)
        self.clearKeyBtn = PushButton(FIF.DELETE, "清空")
        self.clearKeyBtn.clicked.connect(self.clearKey)
        
        btnLayout.addWidget(self.genKeyBtn)
        btnLayout.addWidget(self.clearKeyBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createAliceCard(self):
        """创建 Alice 签名卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("👩 步骤2：Alice 对消息签名")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 消息
        msgLabel = BodyLabel("消息 (Message)")
        layout.addWidget(msgLabel)
        self.aliceMessageEdit = LineEdit()
        self.aliceMessageEdit.setText("Hello Bob!")
        self.aliceMessageEdit.setPlaceholderText("输入要签名的消息...")
        layout.addWidget(self.aliceMessageEdit)
        
        # 签名
        sigLabel = BodyLabel("签名 (Signature)")
        layout.addWidget(sigLabel)
        self.aliceSignatureEdit = TextEdit()
        self.aliceSignatureEdit.setReadOnly(True)
        self.aliceSignatureEdit.setMaximumHeight(80)
        self.aliceSignatureEdit.setPlaceholderText("签名结果将显示在这里...")
        layout.addWidget(self.aliceSignatureEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.signBtn = PrimaryPushButton(FIF.EDIT, "签名")
        self.signBtn.clicked.connect(self.sign)
        self.clearAliceBtn = PushButton(FIF.DELETE, "清空")
        self.clearAliceBtn.clicked.connect(self.clearAlice)
        
        btnLayout.addWidget(self.signBtn)
        btnLayout.addWidget(self.clearAliceBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createAttackerCard(self):
        """创建攻击者卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🦹 步骤3：攻击者截获并重放")
        title.setStyleSheet("font-weight: bold; font-size: 14px; color: #d13438;")
        layout.addWidget(title)
        
        desc = BodyLabel("攻击者截获 Alice 的消息和签名，尝试重放给 Bob")
        desc.setStyleSheet("color: #d13438;")
        layout.addWidget(desc)
        
        # 截获的消息
        msgLabel = BodyLabel("截获的消息")
        layout.addWidget(msgLabel)
        self.attackerMessageEdit = TextEdit()
        self.attackerMessageEdit.setReadOnly(True)
        self.attackerMessageEdit.setMaximumHeight(60)
        self.attackerMessageEdit.setPlaceholderText("点击'截获'按钮...")
        layout.addWidget(self.attackerMessageEdit)
        
        # 截获的签名
        sigLabel = BodyLabel("截获的签名")
        layout.addWidget(sigLabel)
        self.attackerSignatureEdit = TextEdit()
        self.attackerSignatureEdit.setMaximumHeight(80)
        self.attackerSignatureEdit.setPlaceholderText("点击'截获'按钮...")
        layout.addWidget(self.attackerSignatureEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.attackBtn = PrimaryPushButton(FIF.COPY, "截获")
        self.attackBtn.clicked.connect(self.attack)
        self.clearAttackerBtn = PushButton(FIF.DELETE, "清空")
        self.clearAttackerBtn.clicked.connect(self.clearAttacker)
        
        btnLayout.addWidget(self.attackBtn)
        btnLayout.addWidget(self.clearAttackerBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createBobCard(self):
        """创建 Bob 验证卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("👨 步骤4：Bob 验证签名")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 验证结果
        resultLabel = BodyLabel("验证结果")
        layout.addWidget(resultLabel)
        self.resultEdit = TextEdit()
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setMaximumHeight(80)
        self.resultEdit.setPlaceholderText("验证结果将显示在这里...")
        layout.addWidget(self.resultEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.verifyAliceBtn = PrimaryPushButton(FIF.ACCEPT, "验证 Alice 签名")
        self.verifyAliceBtn.clicked.connect(self.verifyAlice)
        self.verifyAttackerBtn = PushButton(FIF.CANCEL, "验证攻击者签名")
        self.verifyAttackerBtn.clicked.connect(self.verifyAttacker)
        self.clearBobBtn = PushButton(FIF.DELETE, "清空")
        self.clearBobBtn.clicked.connect(self.clearBob)
        
        btnLayout.addWidget(self.verifyAliceBtn)
        btnLayout.addWidget(self.verifyAttackerBtn)
        btnLayout.addWidget(self.clearBobBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createLogCard(self):
        """创建日志卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(8)
        
        title = BodyLabel("📊 操作日志")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        self.logEdit = TextEdit()
        self.logEdit.setReadOnly(True)
        self.logEdit.setMaximumHeight(150)
        layout.addWidget(self.logEdit)
        
        btnLayout = QHBoxLayout()
        self.clearLogBtn = PushButton(FIF.DELETE, "清空日志")
        self.clearLogBtn.clicked.connect(lambda: self.logEdit.clear())
        btnLayout.addWidget(self.clearLogBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    # ========== 功能实现 ==========
    
    def generateKey(self):
        """生成 ECC 密钥对"""
        try:
            self.log("正在生成 ECC P-256 密钥对...", "info")
            
            # 生成密钥
            self.key = ECC.generate(curve='P-256')
            
            # 格式化私钥
            private_key = hex(self.key.d).replace("0x", "")
            private_key_formatted = str_add_space(private_key).upper()
            
            # 格式化公钥
            public_key = hex(self.key.pointQ.x).replace("0x", "") + hex(self.key.pointQ.y).replace("0x", "")
            public_key_formatted = str_add_space(public_key).upper()
            
            # 显示
            self.privateKeyEdit.setPlainText(private_key_formatted)
            self.publicKeyEdit.setPlainText(public_key_formatted)
            
            self.log(f"私钥: {private_key_formatted[:50]}...", "success")
            self.log(f"公钥: {public_key_formatted[:50]}...", "success")
            
            InfoBar.success(
                title="生成成功",
                content="ECC P-256 密钥对已生成",
                parent=self
            )
        except Exception as e:
            self.log(f"生成密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成密钥失败: {str(e)}", self).exec()
    
    def sign(self):
        """Alice 对消息签名"""
        try:
            if self.key is None:
                InfoBar.warning(
                    title="请先生成密钥",
                    content="需要先生成密钥对才能签名",
                    parent=self
                )
                return
            
            message = self.aliceMessageEdit.text()
            if not message:
                InfoBar.warning(
                    title="消息为空",
                    content="请输入要签名的消息",
                    parent=self
                )
                return
            
            self.log(f"Alice 正在对消息签名: {message}", "info")
            
            # 创建签名线程
            thread = SignThread(message.encode(), self.key)
            thread.finished.connect(self.onSignFinished)
            thread.start()
            
        except Exception as e:
            self.log(f"签名失败: {str(e)}", "error")
            MessageBox("错误", f"签名失败: {str(e)}", self).exec()
    
    def onSignFinished(self, signature):
        """签名完成"""
        self.aliceSignatureEdit.setPlainText(signature)
        self.log(f"签名: {signature[:50]}...", "success")
        InfoBar.success(
            title="签名成功",
            content="消息已成功签名",
            parent=self
        )
    
    def attack(self):
        """攻击者截获消息和签名"""
        try:
            message = self.aliceMessageEdit.text()
            signature = self.aliceSignatureEdit.toPlainText()
            
            if not message or not signature:
                InfoBar.warning(
                    title="无法截获",
                    content="Alice 还没有签名消息",
                    parent=self
                )
                return
            
            self.log("⚠️ 攻击者截获了 Alice 的消息和签名！", "warning")
            
            # 复制到攻击者区域
            self.attackerMessageEdit.setPlainText(message)
            self.attackerSignatureEdit.setPlainText(signature)
            
            InfoBar.warning(
                title="消息被截获",
                content="攻击者已截获 Alice 的消息和签名",
                parent=self
            )
        except Exception as e:
            self.log(f"截获失败: {str(e)}", "error")
    
    def verifyAlice(self):
        """验证 Alice 的签名"""
        try:
            if self.key is None:
                InfoBar.warning(
                    title="请先生成密钥",
                    content="需要先生成密钥对",
                    parent=self
                )
                return
            
            message = self.aliceMessageEdit.text()
            signature_hex = self.aliceSignatureEdit.toPlainText().replace(" ", "")
            
            if not message or not signature_hex:
                InfoBar.warning(
                    title="数据不完整",
                    content="需要消息和签名",
                    parent=self
                )
                return
            
            self.log("Bob 正在验证 Alice 的签名...", "info")
            
            # 转换签名
            signature = bytes.fromhex(signature_hex)
            
            # 创建验证线程
            thread = VerifyThread(message.encode(), signature, self.key)
            thread.finished.connect(self.onVerifyFinished)
            thread.start()
            
        except Exception as e:
            self.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    def verifyAttacker(self):
        """验证攻击者的签名"""
        try:
            if self.key is None:
                InfoBar.warning(
                    title="请先生成密钥",
                    content="需要先生成密钥对",
                    parent=self
                )
                return
            
            message = self.attackerMessageEdit.toPlainText()
            signature_hex = self.attackerSignatureEdit.toPlainText().replace(" ", "")
            
            if not message or not signature_hex:
                InfoBar.warning(
                    title="数据不完整",
                    content="攻击者还没有截获数据",
                    parent=self
                )
                return
            
            self.log("Bob 正在验证攻击者重放的签名...", "info")
            
            # 转换签名
            signature = bytes.fromhex(signature_hex)
            
            # 创建验证线程
            thread = VerifyThread(message.encode(), signature, self.key)
            thread.finished.connect(self.onVerifyFinished)
            thread.start()
            
        except Exception as e:
            self.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    def onVerifyFinished(self, result):
        """验证完成"""
        self.resultEdit.setPlainText(result)
        self.log(result, "success" if "成功" in result else "error")
        
        if "成功" in result:
            InfoBar.success(
                title="验证成功",
                content="签名有效",
                parent=self
            )
        else:
            InfoBar.error(
                title="验证失败",
                content="签名无效",
                parent=self
            )
    
    # ========== 清空功能 ==========
    
    def clearKey(self):
        """清空密钥"""
        self.privateKeyEdit.clear()
        self.publicKeyEdit.clear()
        self.key = None
        self.log("已清空密钥", "info")
    
    def clearAlice(self):
        """清空 Alice 区域"""
        self.aliceSignatureEdit.clear()
        self.log("已清空 Alice 签名", "info")
    
    def clearAttacker(self):
        """清空攻击者区域"""
        self.attackerMessageEdit.clear()
        self.attackerSignatureEdit.clear()
        self.log("已清空攻击者数据", "info")
    
    def clearBob(self):
        """清空 Bob 区域"""
        self.resultEdit.clear()
        self.log("已清空验证结果", "info")
    
    # ========== 日志功能 ==========
    
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
