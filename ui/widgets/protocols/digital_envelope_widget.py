"""
数字信封 - Fluent Design 版本

演示场景：
数字信封是一种结合对称加密和非对称加密的混合加密方案。
发送方使用对称密钥（AES）加密消息，然后用接收方的公钥（RSA）加密对称密钥。

协议步骤：
1. 接收方生成RSA密钥对（公钥和私钥）
2. 发送方：
   - 生成随机AES密钥
   - 使用AES密钥加密明文消息
   - 使用接收方的RSA公钥加密AES密钥
   - 发送：加密的AES密钥 + 加密的消息
3. 接收方：
   - 使用RSA私钥解密AES密钥
   - 使用AES密钥解密消息

优点：结合了对称加密的高效和非对称加密的安全密钥交换
"""

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    InfoBar, MessageBox, FluentIcon as FIF
)

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import secrets


def str_add_space(out_str: str) -> str:
    """每2个字符添加一个空格"""
    add_space_str = ''
    for i in range(int(len(out_str) / 2)):
        add_space_str += out_str[i * 2:i * 2 + 2]
        add_space_str += ' '
    return add_space_str.strip()


class KeyGenThread(QThread):
    """RSA密钥生成线程"""
    finished = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
    
    def run(self):
        try:
            # 生成2048位RSA密钥
            key = RSA.generate(2048)
            self.finished.emit(key)
        except Exception as e:
            self.finished.emit(None)


class EncryptThread(QThread):
    """加密线程"""
    finished = pyqtSignal(str, str)
    
    def __init__(self, plaintext, aes_key, rsa_public_key):
        super().__init__()
        self.plaintext = plaintext
        self.aes_key = aes_key
        self.rsa_public_key = rsa_public_key
    
    def run(self):
        try:
            # AES加密消息
            cipher_aes = AES.new(self.aes_key, AES.MODE_ECB)
            padded_plaintext = pad(self.plaintext, AES.block_size)
            encrypted_message = cipher_aes.encrypt(padded_plaintext)
            
            # RSA加密AES密钥
            cipher_rsa = PKCS1_OAEP.new(self.rsa_public_key)
            encrypted_key = cipher_rsa.encrypt(self.aes_key)
            
            # 格式化输出
            encrypted_key_hex = encrypted_key.hex().upper()
            encrypted_message_hex = encrypted_message.hex().upper()
            
            encrypted_key_formatted = str_add_space(encrypted_key_hex)
            encrypted_message_formatted = str_add_space(encrypted_message_hex)
            
            self.finished.emit(encrypted_key_formatted, encrypted_message_formatted)
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}", "")


class DecryptThread(QThread):
    """解密线程"""
    finished = pyqtSignal(str, str)
    
    def __init__(self, encrypted_key, encrypted_message, rsa_private_key):
        super().__init__()
        self.encrypted_key = encrypted_key
        self.encrypted_message = encrypted_message
        self.rsa_private_key = rsa_private_key
    
    def run(self):
        try:
            # RSA解密AES密钥
            cipher_rsa = PKCS1_OAEP.new(self.rsa_private_key)
            aes_key = cipher_rsa.decrypt(self.encrypted_key)
            
            # AES解密消息
            cipher_aes = AES.new(aes_key, AES.MODE_ECB)
            padded_plaintext = cipher_aes.decrypt(self.encrypted_message)
            plaintext = unpad(padded_plaintext, AES.block_size)
            
            # 格式化输出
            aes_key_hex = aes_key.hex().upper()
            plaintext_hex = plaintext.hex().upper()
            
            aes_key_formatted = str_add_space(aes_key_hex)
            plaintext_formatted = str_add_space(plaintext_hex)
            
            self.finished.emit(aes_key_formatted, plaintext_formatted)
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}", "")


class DigitalEnvelopeWidget(ScrollArea):
    """数字信封演示界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("digitalEnvelopeWidget")
        self.rsa_key = None
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
        title = TitleLabel("数字信封")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "混合加密方案：使用AES加密消息（快速），使用RSA加密AES密钥（安全）。\n"
            "结合了对称加密的效率和非对称加密的安全密钥交换。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 1. 密钥生成卡片
        self.keyCard = self.createKeyCard()
        layout.addWidget(self.keyCard)
        
        # 2. 加密卡片
        self.encryptCard = self.createEncryptCard()
        layout.addWidget(self.encryptCard)
        
        # 3. 解密卡片
        self.decryptCard = self.createDecryptCard()
        layout.addWidget(self.decryptCard)
        
        # 4. 日志卡片
        self.logCard = self.createLogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        self.log("数字信封演示已加载", "success")
    
    def createKeyCard(self):
        """创建密钥生成卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔑 步骤1：生成RSA密钥对")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 公钥
        pubLabel = BodyLabel("公钥 (Public Key) - 2048位")
        layout.addWidget(pubLabel)
        self.publicKeyEdit = TextEdit()
        self.publicKeyEdit.setReadOnly(True)
        self.publicKeyEdit.setMaximumHeight(100)
        self.publicKeyEdit.setPlaceholderText("点击生成密钥...")
        layout.addWidget(self.publicKeyEdit)
        
        # 私钥
        privLabel = BodyLabel("私钥 (Private Key) - 2048位")
        layout.addWidget(privLabel)
        self.privateKeyEdit = TextEdit()
        self.privateKeyEdit.setReadOnly(True)
        self.privateKeyEdit.setMaximumHeight(100)
        self.privateKeyEdit.setPlaceholderText("点击生成密钥...")
        layout.addWidget(self.privateKeyEdit)
        
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
    
    def createEncryptCard(self):
        """创建加密卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔒 步骤2：发送方加密")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 明文
        plainLabel = BodyLabel("明文 (Plaintext) - 16字节")
        layout.addWidget(plainLabel)
        self.plaintextEdit = LineEdit()
        self.plaintextEdit.setText("11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00")
        self.plaintextEdit.setPlaceholderText("输入16字节明文（十六进制）...")
        layout.addWidget(self.plaintextEdit)
        
        # AES密钥
        aesKeyLabel = BodyLabel("AES密钥 (Symmetric Key) - 16字节")
        layout.addWidget(aesKeyLabel)
        self.aesKeyEdit = LineEdit()
        self.aesKeyEdit.setText("01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10")
        self.aesKeyEdit.setPlaceholderText("输入16字节AES密钥（十六进制）...")
        layout.addWidget(self.aesKeyEdit)
        
        # 加密的AES密钥
        encKeyLabel = BodyLabel("加密的AES密钥 (Encrypted Key)")
        layout.addWidget(encKeyLabel)
        self.encryptedKeyEdit = TextEdit()
        self.encryptedKeyEdit.setReadOnly(True)
        self.encryptedKeyEdit.setMaximumHeight(80)
        self.encryptedKeyEdit.setPlaceholderText("加密结果...")
        layout.addWidget(self.encryptedKeyEdit)
        
        # 加密的消息
        encMsgLabel = BodyLabel("加密的消息 (Encrypted Message)")
        layout.addWidget(encMsgLabel)
        self.encryptedMessageEdit = TextEdit()
        self.encryptedMessageEdit.setReadOnly(True)
        self.encryptedMessageEdit.setMaximumHeight(60)
        self.encryptedMessageEdit.setPlaceholderText("加密结果...")
        layout.addWidget(self.encryptedMessageEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.encryptBtn = PrimaryPushButton(FIF.LOCK, "加密")
        self.encryptBtn.clicked.connect(self.encrypt)
        self.clearEncryptBtn = PushButton(FIF.DELETE, "清空")
        self.clearEncryptBtn.clicked.connect(self.clearEncrypt)
        
        btnLayout.addWidget(self.encryptBtn)
        btnLayout.addWidget(self.clearEncryptBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createDecryptCard(self):
        """创建解密卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔓 步骤3：接收方解密")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 待解密的AES密钥
        decKeyLabel = BodyLabel("待解密的AES密钥")
        layout.addWidget(decKeyLabel)
        self.decryptKeyEdit = TextEdit()
        self.decryptKeyEdit.setMaximumHeight(80)
        self.decryptKeyEdit.setPlaceholderText("点击'加密'后自动填充...")
        layout.addWidget(self.decryptKeyEdit)
        
        # 待解密的消息
        decMsgLabel = BodyLabel("待解密的消息")
        layout.addWidget(decMsgLabel)
        self.decryptMessageEdit = TextEdit()
        self.decryptMessageEdit.setMaximumHeight(60)
        self.decryptMessageEdit.setPlaceholderText("点击'加密'后自动填充...")
        layout.addWidget(self.decryptMessageEdit)
        
        # 解密的AES密钥
        decryptedKeyLabel = BodyLabel("解密的AES密钥")
        layout.addWidget(decryptedKeyLabel)
        self.decryptedKeyEdit = LineEdit()
        self.decryptedKeyEdit.setReadOnly(True)
        self.decryptedKeyEdit.setPlaceholderText("解密结果...")
        layout.addWidget(self.decryptedKeyEdit)
        
        # 解密的明文
        decryptedPlainLabel = BodyLabel("解密的明文")
        layout.addWidget(decryptedPlainLabel)
        self.decryptedPlaintextEdit = LineEdit()
        self.decryptedPlaintextEdit.setReadOnly(True)
        self.decryptedPlaintextEdit.setPlaceholderText("解密结果...")
        layout.addWidget(self.decryptedPlaintextEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.decryptBtn = PrimaryPushButton(FIF.UNLOCK, "解密")
        self.decryptBtn.clicked.connect(self.decrypt)
        self.clearDecryptBtn = PushButton(FIF.DELETE, "清空")
        self.clearDecryptBtn.clicked.connect(self.clearDecrypt)
        
        btnLayout.addWidget(self.decryptBtn)
        btnLayout.addWidget(self.clearDecryptBtn)
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
        """生成RSA密钥对"""
        try:
            self.log("正在生成2048位RSA密钥对...", "info")
            self.genKeyBtn.setEnabled(False)
            
            # 创建密钥生成线程
            self.keyGenThread = KeyGenThread()
            self.keyGenThread.finished.connect(self.onKeyGenFinished)
            self.keyGenThread.start()
            
        except Exception as e:
            self.log(f"生成密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
            self.genKeyBtn.setEnabled(True)
    
    def onKeyGenFinished(self, key):
        """密钥生成完成"""
        self.genKeyBtn.setEnabled(True)
        
        if key is None:
            self.log("生成密钥失败", "error")
            MessageBox("错误", "生成密钥失败", self).exec()
            return
        
        self.rsa_key = key
        
        # 导出公钥和私钥（PEM格式）
        public_pem = key.publickey().export_key().decode()
        private_pem = key.export_key().decode()
        
        self.publicKeyEdit.setPlainText(public_pem)
        self.privateKeyEdit.setPlainText(private_pem)
        
        self.log("RSA密钥对生成成功", "success")
        self.log(f"公钥长度: {key.size_in_bits()} 位", "info")
        
        InfoBar.success(
            title="生成成功",
            content="2048位RSA密钥对已生成",
            parent=self
        )
    
    def encrypt(self):
        """加密"""
        try:
            if self.rsa_key is None:
                InfoBar.warning(
                    title="密钥未生成",
                    content="请先生成RSA密钥对",
                    parent=self
                )
                return
            
            # 获取明文
            plaintext_str = self.plaintextEdit.text().replace(" ", "")
            if len(plaintext_str) != 32:  # 16字节 = 32个十六进制字符
                InfoBar.warning(
                    title="明文长度错误",
                    content="明文必须是16字节（32个十六进制字符）",
                    parent=self
                )
                return
            
            # 获取AES密钥
            aes_key_str = self.aesKeyEdit.text().replace(" ", "")
            if len(aes_key_str) != 32:  # 16字节 = 32个十六进制字符
                InfoBar.warning(
                    title="AES密钥长度错误",
                    content="AES密钥必须是16字节（32个十六进制字符）",
                    parent=self
                )
                return
            
            plaintext = bytes.fromhex(plaintext_str)
            aes_key = bytes.fromhex(aes_key_str)
            
            self.log("开始加密...", "info")
            self.log(f"明文: {str_add_space(plaintext_str.upper())}", "info")
            self.log(f"AES密钥: {str_add_space(aes_key_str.upper())}", "info")
            
            # 创建加密线程
            self.encryptThread = EncryptThread(plaintext, aes_key, self.rsa_key.publickey())
            self.encryptThread.finished.connect(self.onEncryptFinished)
            self.encryptThread.start()
            
        except ValueError:
            InfoBar.error(
                title="格式错误",
                content="输入必须是有效的十六进制字符",
                parent=self
            )
        except Exception as e:
            self.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, encrypted_key, encrypted_message):
        """加密完成"""
        if "Error" in encrypted_key:
            self.log(f"加密失败: {encrypted_key}", "error")
            MessageBox("错误", f"加密失败: {encrypted_key}", self).exec()
            return
        
        self.encryptedKeyEdit.setPlainText(encrypted_key)
        self.encryptedMessageEdit.setPlainText(encrypted_message)
        
        # 自动填充到解密区域
        self.decryptKeyEdit.setPlainText(encrypted_key)
        self.decryptMessageEdit.setPlainText(encrypted_message)
        
        self.log(f"加密的AES密钥: {encrypted_key[:50]}...", "success")
        self.log(f"加密的消息: {encrypted_message}", "success")
        
        InfoBar.success(
            title="加密成功",
            content="数字信封已创建",
            parent=self
        )
    
    def decrypt(self):
        """解密"""
        try:
            if self.rsa_key is None:
                InfoBar.warning(
                    title="密钥未生成",
                    content="请先生成RSA密钥对",
                    parent=self
                )
                return
            
            # 获取加密的数据
            encrypted_key_str = self.decryptKeyEdit.toPlainText().replace(" ", "")
            encrypted_message_str = self.decryptMessageEdit.toPlainText().replace(" ", "")
            
            if not encrypted_key_str or not encrypted_message_str:
                InfoBar.warning(
                    title="数据不完整",
                    content="请先进行加密操作",
                    parent=self
                )
                return
            
            encrypted_key = bytes.fromhex(encrypted_key_str)
            encrypted_message = bytes.fromhex(encrypted_message_str)
            
            self.log("开始解密...", "info")
            
            # 创建解密线程
            self.decryptThread = DecryptThread(encrypted_key, encrypted_message, self.rsa_key)
            self.decryptThread.finished.connect(self.onDecryptFinished)
            self.decryptThread.start()
            
        except ValueError:
            InfoBar.error(
                title="格式错误",
                content="输入必须是有效的十六进制字符",
                parent=self
            )
        except Exception as e:
            self.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, aes_key, plaintext):
        """解密完成"""
        if "Error" in aes_key:
            self.log(f"解密失败: {aes_key}", "error")
            MessageBox("错误", f"解密失败: {aes_key}", self).exec()
            return
        
        self.decryptedKeyEdit.setText(aes_key)
        self.decryptedPlaintextEdit.setText(plaintext)
        
        self.log(f"解密的AES密钥: {aes_key}", "success")
        self.log(f"解密的明文: {plaintext}", "success")
        
        # 验证
        original_key = self.aesKeyEdit.text().replace(" ", "").upper()
        original_plain = self.plaintextEdit.text().replace(" ", "").upper()
        decrypted_key = aes_key.replace(" ", "")
        decrypted_plain = plaintext.replace(" ", "")
        
        if original_key == decrypted_key and original_plain == decrypted_plain:
            self.log("✅ 验证成功：解密结果与原始数据一致", "success")
            InfoBar.success(
                title="解密成功",
                content="数字信封已打开，数据验证通过",
                parent=self
            )
        else:
            self.log("❌ 验证失败：解密结果与原始数据不一致", "error")
            InfoBar.error(
                title="验证失败",
                content="解密结果与原始数据不一致",
                parent=self
            )
    
    # ========== 清空功能 ==========
    
    def clearKey(self):
        """清空密钥"""
        self.publicKeyEdit.clear()
        self.privateKeyEdit.clear()
        self.rsa_key = None
        self.log("已清空密钥", "info")
    
    def clearEncrypt(self):
        """清空加密区域"""
        self.encryptedKeyEdit.clear()
        self.encryptedMessageEdit.clear()
        self.log("已清空加密数据", "info")
    
    def clearDecrypt(self):
        """清空解密区域"""
        self.decryptKeyEdit.clear()
        self.decryptMessageEdit.clear()
        self.decryptedKeyEdit.clear()
        self.decryptedPlaintextEdit.clear()
        self.log("已清空解密数据", "info")
    
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
