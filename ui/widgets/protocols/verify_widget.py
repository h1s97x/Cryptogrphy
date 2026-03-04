"""
Verify 协议演示 - Fluent Design 版本

演示场景：
1. PC 和智能卡各自初始化密钥
2. PC 生成随机挑战（Challenge）并发送给智能卡
3. 智能卡使用密钥加密挑战，返回响应（Response）
4. PC 使用自己的密钥解密响应，验证是否与原始挑战一致

注：本版本移除了智能卡依赖，使用纯软件模拟
"""

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    InfoBar, MessageBox, FluentIcon as FIF
)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets


def str_add_space(out_str: str) -> str:
    """每2个字符添加一个空格"""
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str.strip()


class EncryptThread(QThread):
    """加密线程（模拟智能卡）"""
    finished = pyqtSignal(str)
    
    def __init__(self, challenge, key):
        super().__init__()
        self.challenge = challenge
        self.key = key
    
    def run(self):
        try:
            # 使用 AES-ECB 加密
            cipher = AES.new(self.key, AES.MODE_ECB)
            response = cipher.encrypt(self.challenge)
            response_hex = response.hex().upper()
            response_formatted = str_add_space(response_hex)
            self.finished.emit(response_formatted)
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}")


class DecryptThread(QThread):
    """解密线程"""
    finished = pyqtSignal(str, str)
    
    def __init__(self, response, key, challenge):
        super().__init__()
        self.response = response
        self.key = key
        self.challenge = challenge
    
    def run(self):
        try:
            # 使用 AES-ECB 解密
            cipher = AES.new(self.key, AES.MODE_ECB)
            decrypted = cipher.decrypt(self.response)
            decrypted_hex = decrypted.hex().upper()
            decrypted_formatted = str_add_space(decrypted_hex)
            
            # 验证
            if decrypted == self.challenge:
                verify_result = "✅ 验证成功 - 挑战和解密结果一致"
            else:
                verify_result = "❌ 验证失败 - 挑战和解密结果不一致"
            
            self.finished.emit(decrypted_formatted, verify_result)
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}", f"Error: {str(e)}")


class VerifyWidget(ScrollArea):
    """Verify 协议演示界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("verifyWidget")
        self.keyForPC = None
        self.keyForCard = None
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
        title = TitleLabel("Verify 协议演示")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "演示场景：PC 向智能卡发送挑战，智能卡加密后返回响应，PC 验证响应的正确性。\n"
            "使用 AES-ECB 模式进行加密验证（纯软件模拟）。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 1. PC 密钥卡片
        self.pcKeyCard = self.createPCKeyCard()
        layout.addWidget(self.pcKeyCard)
        
        # 2. 智能卡密钥卡片
        self.cardKeyCard = self.createCardKeyCard()
        layout.addWidget(self.cardKeyCard)
        
        # 3. 挑战卡片
        self.challengeCard = self.createChallengeCard()
        layout.addWidget(self.challengeCard)
        
        # 4. 响应卡片
        self.responseCard = self.createResponseCard()
        layout.addWidget(self.responseCard)
        
        # 5. 验证卡片
        self.verifyCard = self.createVerifyCard()
        layout.addWidget(self.verifyCard)
        
        # 6. 日志卡片
        self.logCard = self.createLogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        self.log("Verify 协议演示已加载", "success")
    
    def createPCKeyCard(self):
        """创建 PC 密钥卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🖥️ PC 密钥")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 密钥
        keyLabel = BodyLabel("密钥 (Key for PC) - 16字节")
        layout.addWidget(keyLabel)
        self.pcKeyEdit = LineEdit()
        self.pcKeyEdit.setText("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")
        self.pcKeyEdit.setPlaceholderText("输入16字节密钥（十六进制）...")
        layout.addWidget(self.pcKeyEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.initPCKeyBtn = PrimaryPushButton(FIF.FINGERPRINT, "初始化密钥")
        self.initPCKeyBtn.clicked.connect(self.initPCKey)
        self.getPCKeyBtn = PushButton(FIF.VIEW, "查看密钥")
        self.getPCKeyBtn.clicked.connect(self.getPCKey)
        self.clearPCKeyBtn = PushButton(FIF.DELETE, "清空")
        self.clearPCKeyBtn.clicked.connect(self.clearPCKey)
        
        btnLayout.addWidget(self.initPCKeyBtn)
        btnLayout.addWidget(self.getPCKeyBtn)
        btnLayout.addWidget(self.clearPCKeyBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createCardKeyCard(self):
        """创建智能卡密钥卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("💳 智能卡密钥（模拟）")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 密钥
        keyLabel = BodyLabel("密钥 (Key for Card) - 16字节")
        layout.addWidget(keyLabel)
        self.cardKeyEdit = LineEdit()
        self.cardKeyEdit.setText("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")
        self.cardKeyEdit.setPlaceholderText("输入16字节密钥（十六进制）...")
        layout.addWidget(self.cardKeyEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.initCardKeyBtn = PrimaryPushButton(FIF.FINGERPRINT, "初始化密钥")
        self.initCardKeyBtn.clicked.connect(self.initCardKey)
        self.getCardKeyBtn = PushButton(FIF.VIEW, "查看密钥")
        self.getCardKeyBtn.clicked.connect(self.getCardKey)
        self.clearCardKeyBtn = PushButton(FIF.DELETE, "清空")
        self.clearCardKeyBtn.clicked.connect(self.clearCardKey)
        
        btnLayout.addWidget(self.initCardKeyBtn)
        btnLayout.addWidget(self.getCardKeyBtn)
        btnLayout.addWidget(self.clearCardKeyBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createChallengeCard(self):
        """创建挑战卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📤 步骤1：PC 发送挑战")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 挑战
        challengeLabel = BodyLabel("挑战 (Challenge) - 16字节")
        layout.addWidget(challengeLabel)
        self.challengeEdit = LineEdit()
        self.challengeEdit.setText("FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00")
        self.challengeEdit.setPlaceholderText("输入16字节挑战（十六进制）...")
        layout.addWidget(self.challengeEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.generateChallengeBtn = PrimaryPushButton(FIF.SYNC, "生成随机挑战")
        self.generateChallengeBtn.clicked.connect(self.generateChallenge)
        self.sendChallengeBtn = PushButton(FIF.SEND, "发送挑战")
        self.sendChallengeBtn.clicked.connect(self.sendChallenge)
        self.clearChallengeBtn = PushButton(FIF.DELETE, "清空")
        self.clearChallengeBtn.clicked.connect(self.clearChallenge)
        
        btnLayout.addWidget(self.generateChallengeBtn)
        btnLayout.addWidget(self.sendChallengeBtn)
        btnLayout.addWidget(self.clearChallengeBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createResponseCard(self):
        """创建响应卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📥 步骤2：获取智能卡响应")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 响应
        responseLabel = BodyLabel("响应 (Response)")
        layout.addWidget(responseLabel)
        self.responseEdit = TextEdit()
        self.responseEdit.setReadOnly(True)
        self.responseEdit.setMaximumHeight(60)
        self.responseEdit.setPlaceholderText("智能卡响应将显示在这里...")
        layout.addWidget(self.responseEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.getResponseBtn = PrimaryPushButton(FIF.DOWNLOAD, "获取响应")
        self.getResponseBtn.clicked.connect(self.getResponse)
        self.clearResponseBtn = PushButton(FIF.DELETE, "清空")
        self.clearResponseBtn.clicked.connect(self.clearResponse)
        
        btnLayout.addWidget(self.getResponseBtn)
        btnLayout.addWidget(self.clearResponseBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createVerifyCard(self):
        """创建验证卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("✅ 步骤3：PC 验证响应")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 待验证的挑战
        challengeLabel = BodyLabel("待验证的挑战")
        layout.addWidget(challengeLabel)
        self.verifyChallengeEdit = LineEdit()
        self.verifyChallengeEdit.setPlaceholderText("点击'发送挑战'后自动填充...")
        layout.addWidget(self.verifyChallengeEdit)
        
        # 待验证的响应
        responseLabel = BodyLabel("待验证的响应")
        layout.addWidget(responseLabel)
        self.verifyResponseEdit = LineEdit()
        self.verifyResponseEdit.setPlaceholderText("点击'获取响应'后自动填充...")
        layout.addWidget(self.verifyResponseEdit)
        
        # 解密结果
        decryptLabel = BodyLabel("解密结果")
        layout.addWidget(decryptLabel)
        self.decryptResultEdit = TextEdit()
        self.decryptResultEdit.setReadOnly(True)
        self.decryptResultEdit.setMaximumHeight(60)
        self.decryptResultEdit.setPlaceholderText("解密结果将显示在这里...")
        layout.addWidget(self.decryptResultEdit)
        
        # 验证结果
        verifyLabel = BodyLabel("验证结果")
        layout.addWidget(verifyLabel)
        self.verifyResultEdit = TextEdit()
        self.verifyResultEdit.setReadOnly(True)
        self.verifyResultEdit.setMaximumHeight(60)
        self.verifyResultEdit.setPlaceholderText("验证结果将显示在这里...")
        layout.addWidget(self.verifyResultEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.verifyBtn = PrimaryPushButton(FIF.ACCEPT, "验证")
        self.verifyBtn.clicked.connect(self.verify)
        self.clearVerifyBtn = PushButton(FIF.DELETE, "清空")
        self.clearVerifyBtn.clicked.connect(self.clearVerify)
        
        btnLayout.addWidget(self.verifyBtn)
        btnLayout.addWidget(self.clearVerifyBtn)
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
    
    def initPCKey(self):
        """初始化 PC 密钥"""
        try:
            key_str = self.pcKeyEdit.text().replace(" ", "")
            if len(key_str) != 32:  # 16字节 = 32个十六进制字符
                InfoBar.warning(
                    title="密钥长度错误",
                    content="密钥必须是16字节（32个十六进制字符）",
                    parent=self
                )
                return
            
            self.keyForPC = bytes.fromhex(key_str)
            formatted = str_add_space(key_str.upper())
            self.pcKeyEdit.setText(formatted)
            
            self.log(f"PC 密钥已初始化: {formatted}", "success")
            InfoBar.success(
                title="初始化成功",
                content="PC 密钥已初始化",
                parent=self
            )
        except ValueError:
            InfoBar.error(
                title="格式错误",
                content="密钥必须是有效的十六进制字符",
                parent=self
            )
        except Exception as e:
            self.log(f"初始化 PC 密钥失败: {str(e)}", "error")
            MessageBox("错误", f"初始化失败: {str(e)}", self).exec()
    
    def getPCKey(self):
        """查看 PC 密钥"""
        if self.keyForPC is None:
            InfoBar.warning(
                title="密钥未初始化",
                content="请先初始化 PC 密钥",
                parent=self
            )
            return
        
        key_hex = self.keyForPC.hex().upper()
        formatted = str_add_space(key_hex)
        self.pcKeyEdit.setText(formatted)
        self.log(f"PC 密钥: {formatted}", "info")
    
    def clearPCKey(self):
        """清空 PC 密钥"""
        self.pcKeyEdit.clear()
        self.keyForPC = None
        self.log("已清空 PC 密钥", "info")
    
    def initCardKey(self):
        """初始化智能卡密钥"""
        try:
            key_str = self.cardKeyEdit.text().replace(" ", "")
            if len(key_str) != 32:  # 16字节 = 32个十六进制字符
                InfoBar.warning(
                    title="密钥长度错误",
                    content="密钥必须是16字节（32个十六进制字符）",
                    parent=self
                )
                return
            
            self.keyForCard = bytes.fromhex(key_str)
            formatted = str_add_space(key_str.upper())
            self.cardKeyEdit.setText(formatted)
            
            self.log(f"智能卡密钥已初始化: {formatted}", "success")
            InfoBar.success(
                title="初始化成功",
                content="智能卡密钥已初始化（模拟）",
                parent=self
            )
        except ValueError:
            InfoBar.error(
                title="格式错误",
                content="密钥必须是有效的十六进制字符",
                parent=self
            )
        except Exception as e:
            self.log(f"初始化智能卡密钥失败: {str(e)}", "error")
            MessageBox("错误", f"初始化失败: {str(e)}", self).exec()
    
    def getCardKey(self):
        """查看智能卡密钥"""
        if self.keyForCard is None:
            InfoBar.warning(
                title="密钥未初始化",
                content="请先初始化智能卡密钥",
                parent=self
            )
            return
        
        key_hex = self.keyForCard.hex().upper()
        formatted = str_add_space(key_hex)
        self.cardKeyEdit.setText(formatted)
        self.log(f"智能卡密钥: {formatted}", "info")
    
    def clearCardKey(self):
        """清空智能卡密钥"""
        self.cardKeyEdit.clear()
        self.keyForCard = None
        self.log("已清空智能卡密钥", "info")
    
    def generateChallenge(self):
        """生成随机挑战"""
        try:
            challenge = secrets.token_bytes(16)
            challenge_hex = challenge.hex().upper()
            formatted = str_add_space(challenge_hex)
            self.challengeEdit.setText(formatted)
            
            self.log(f"生成随机挑战: {formatted}", "success")
            InfoBar.success(
                title="生成成功",
                content="已生成16字节随机挑战",
                parent=self
            )
        except Exception as e:
            self.log(f"生成挑战失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
    
    def sendChallenge(self):
        """发送挑战到智能卡"""
        try:
            if self.keyForCard is None:
                InfoBar.warning(
                    title="密钥未初始化",
                    content="请先初始化智能卡密钥",
                    parent=self
                )
                return
            
            challenge_str = self.challengeEdit.text().replace(" ", "")
            if len(challenge_str) != 32:
                InfoBar.warning(
                    title="挑战长度错误",
                    content="挑战必须是16字节（32个十六进制字符）",
                    parent=self
                )
                return
            
            challenge = bytes.fromhex(challenge_str)
            formatted = str_add_space(challenge_str.upper())
            self.challengeEdit.setText(formatted)
            
            # 复制到验证区域
            self.verifyChallengeEdit.setText(formatted)
            
            self.log(f"发送挑战到智能卡: {formatted}", "info")
            self.log("智能卡正在加密挑战...", "info")
            
            # 创建加密线程（模拟智能卡）
            self.encryptThread = EncryptThread(challenge, self.keyForCard)
            self.encryptThread.finished.connect(self.onEncryptFinished)
            self.encryptThread.start()
            
        except ValueError:
            InfoBar.error(
                title="格式错误",
                content="挑战必须是有效的十六进制字符",
                parent=self
            )
        except Exception as e:
            self.log(f"发送挑战失败: {str(e)}", "error")
            MessageBox("错误", f"发送失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, response):
        """加密完成"""
        self.responseEdit.setPlainText(response)
        self.log(f"智能卡响应: {response}", "success")
        InfoBar.success(
            title="加密完成",
            content="智能卡已返回响应",
            parent=self
        )
    
    def getResponse(self):
        """获取智能卡响应"""
        response = self.responseEdit.toPlainText()
        if not response:
            InfoBar.warning(
                title="无响应",
                content="请先发送挑战",
                parent=self
            )
            return
        
        # 复制到验证区域
        self.verifyResponseEdit.setText(response)
        self.log("已获取智能卡响应", "info")
    
    def clearChallenge(self):
        """清空挑战"""
        self.challengeEdit.clear()
        self.log("已清空挑战", "info")
    
    def clearResponse(self):
        """清空响应"""
        self.responseEdit.clear()
        self.log("已清空响应", "info")
    
    def verify(self):
        """验证响应"""
        try:
            if self.keyForPC is None:
                InfoBar.warning(
                    title="密钥未初始化",
                    content="请先初始化 PC 密钥",
                    parent=self
                )
                return
            
            challenge_str = self.verifyChallengeEdit.text().replace(" ", "")
            response_str = self.verifyResponseEdit.text().replace(" ", "")
            
            if not challenge_str or not response_str:
                InfoBar.warning(
                    title="数据不完整",
                    content="请先发送挑战并获取响应",
                    parent=self
                )
                return
            
            if len(challenge_str) != 32 or len(response_str) != 32:
                InfoBar.warning(
                    title="数据长度错误",
                    content="挑战和响应必须都是16字节",
                    parent=self
                )
                return
            
            challenge = bytes.fromhex(challenge_str)
            response = bytes.fromhex(response_str)
            
            self.log("PC 正在验证响应...", "info")
            
            # 创建解密线程
            self.decryptThread = DecryptThread(response, self.keyForPC, challenge)
            self.decryptThread.finished.connect(self.onVerifyFinished)
            self.decryptThread.start()
            
        except ValueError:
            InfoBar.error(
                title="格式错误",
                content="数据必须是有效的十六进制字符",
                parent=self
            )
        except Exception as e:
            self.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    def onVerifyFinished(self, decrypted, verify_result):
        """验证完成"""
        self.decryptResultEdit.setPlainText(decrypted)
        self.verifyResultEdit.setPlainText(verify_result)
        
        self.log(f"解密结果: {decrypted}", "info")
        self.log(verify_result, "success" if "成功" in verify_result else "error")
        
        if "成功" in verify_result:
            InfoBar.success(
                title="验证成功",
                content="挑战和解密结果一致",
                parent=self
            )
        else:
            InfoBar.error(
                title="验证失败",
                content="挑战和解密结果不一致",
                parent=self
            )
    
    def clearVerify(self):
        """清空验证区域"""
        self.verifyChallengeEdit.clear()
        self.verifyResponseEdit.clear()
        self.decryptResultEdit.clear()
        self.verifyResultEdit.clear()
        self.log("已清空验证区域", "info")
    
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
