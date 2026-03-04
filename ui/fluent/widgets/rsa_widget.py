"""
RSA 加密算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, TextEdit, PrimaryPushButton,
    FluentIcon as FIF
)

from ui.fluent.components.algorithm_card import EncryptCard, DecryptCard, LogCard
from core.algorithms.asymmetric import RSA
from infrastructure.converters import TypeConvert


class RSAKeyCard(CardWidget):
    """RSA密钥卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔑 RSA 密钥对")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 公钥参数
        self.nEdit = TextEdit()
        self.nEdit.setPlaceholderText("N (模数)")
        self.nEdit.setReadOnly(True)
        self.nEdit.setMaximumHeight(60)
        layout.addWidget(BodyLabel("N (模数)"))
        layout.addWidget(self.nEdit)
        
        self.eEdit = TextEdit()
        self.eEdit.setPlaceholderText("e (公钥指数)")
        self.eEdit.setReadOnly(True)
        self.eEdit.setMaximumHeight(40)
        layout.addWidget(BodyLabel("e (公钥指数)"))
        layout.addWidget(self.eEdit)
        
        # 私钥参数
        self.dEdit = TextEdit()
        self.dEdit.setPlaceholderText("d (私钥指数)")
        self.dEdit.setReadOnly(True)
        self.dEdit.setMaximumHeight(60)
        layout.addWidget(BodyLabel("d (私钥指数)"))
        layout.addWidget(self.dEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.generateBtn = PrimaryPushButton(FIF.SYNC, "生成密钥对")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.generateBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def setKey(self, n, e, d):
        """设置密钥"""
        self.nEdit.setPlainText(n)
        self.eEdit.setPlainText(e)
        self.dEdit.setPlainText(d)
    
    def clear(self):
        """清空"""
        self.nEdit.clear()
        self.eEdit.clear()
        self.dEdit.clear()


class RSAWidget(ScrollArea):
    """RSA 加密算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("rsaWidget")
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
        title = TitleLabel("RSA 加密")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "RSA 是一种非对称加密算法，使用公钥加密、私钥解密。"
            "密钥长度为1024位，输入格式为十六进制（128字节）。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥卡片
        self.keyCard = RSAKeyCard()
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        default_plaintext = "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 " * 8
        self.encryptCard.plaintextEdit.setPlainText(default_plaintext.strip())
        self.encryptCard.plaintextEdit.setPlaceholderText("输入128字节明文（十六进制）...")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        self.decryptCard.ciphertextEdit.setPlaceholderText("输入128字节密文（十六进制）...")
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("RSA 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 密钥卡片
        self.keyCard.generateBtn.clicked.connect(self.generateKey)
        self.keyCard.clearBtn.clicked.connect(self.clearKey)
        
        # 加密卡片
        self.encryptCard.encryptBtn.clicked.connect(self.encrypt)
        self.encryptCard.copyBtn.clicked.connect(self.copyCiphertext)
        self.encryptCard.clearBtn.clicked.connect(self.encryptCard.clear)
        
        # 解密卡片
        self.decryptCard.decryptBtn.clicked.connect(self.decrypt)
        self.decryptCard.copyBtn.clicked.connect(self.copyPlaintext)
    
    def generateKey(self):
        """生成密钥对"""
        try:
            self.logCard.log("正在生成RSA密钥对...", "info")
            
            thread = RSA.KeyThread(self)
            thread.call_back.connect(self.onKeyGenerated)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"生成密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成密钥失败: {str(e)}", self).exec()
    
    def onKeyGenerated(self, key):
        """密钥生成完成"""
        self.key = key
        private_key = key[1]
        
        # 格式化显示
        n_str = TypeConvert.int_to_str(private_key.n, 128)
        e_str = TypeConvert.int_to_str(private_key.e, 4)
        d_str = TypeConvert.int_to_str(private_key.d, 128)
        
        self.keyCard.setKey(n_str, e_str, d_str)
        
        self.logCard.log("密钥对生成完成", "success")
        self.logCard.log(f"N: {n_str[:50]}...", "info")
        self.logCard.log(f"e: {e_str}", "info")
        self.logCard.log(f"d: {d_str[:50]}...", "info")
        
        InfoBar.success(
            title="生成成功",
            content="RSA密钥对已生成",
            parent=self
        )
    
    def clearKey(self):
        """清空密钥"""
        self.keyCard.clear()
        self.key = None
        self.logCard.log("密钥已清空", "info")
    
    def validateHexInput(self, text, name, expected_length=128):
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
            
            # 检查密钥
            if self.key is None:
                raise ValueError("请先生成密钥对")
            
            # 验证明文
            plaintext_text = self.encryptCard.getPlaintext()
            valid, result = self.validateHexInput(plaintext_text, "明文", 128)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            plaintext = TypeConvert.str_to_int(plaintext_text)
            
            # 检查明文是否小于N
            if plaintext >= self.key[0].n:
                raise ValueError("明文太大，必须小于模数N")
            
            # 格式化显示
            plaintext_formatted = TypeConvert.int_to_str(plaintext, 128)
            self.encryptCard.setPlaintext(plaintext_formatted)
            
            self.logCard.log(f"明文: {plaintext_formatted[:50]}...", "info")
            self.logCard.log(f"使用公钥 (e, N) 加密", "info")
            
            # 转换为字节
            plaintext_bytes = bytes(result)
            
            # 创建加密线程
            thread = RSA.RsaThread(parent=self, input_bytes=plaintext_bytes, key=self.key, encrypt_selected=0)
            thread.call_back.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, ciphertext):
        """加密完成"""
        self.encryptCard.setCiphertext(ciphertext)
        self.decryptCard.setCiphertext(ciphertext)
        self.logCard.log(f"密文: {ciphertext[:50]}...", "success")
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
            
            # 检查密钥
            if self.key is None:
                raise ValueError("请先生成密钥对")
            
            # 验证密文
            ciphertext_text = self.decryptCard.getCiphertext()
            valid, result = self.validateHexInput(ciphertext_text, "密文", 128)
            if not valid:
                raise ValueError(result)
            
            # 转换为整数
            ciphertext = TypeConvert.str_to_int(ciphertext_text)
            
            # 格式化显示
            ciphertext_formatted = TypeConvert.int_to_str(ciphertext, 128)
            self.decryptCard.setCiphertext(ciphertext_formatted)
            
            self.logCard.log(f"密文: {ciphertext_formatted[:50]}...", "info")
            self.logCard.log(f"使用私钥 (d, N) 解密", "info")
            
            # 转换为字节
            ciphertext_bytes = bytes(result)
            
            # 创建解密线程
            thread = RSA.RsaThread(parent=self, input_bytes=ciphertext_bytes, key=self.key, encrypt_selected=1)
            thread.call_back.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, plaintext):
        """解密完成"""
        self.decryptCard.setPlaintext(plaintext)
        self.logCard.log(f"明文: {plaintext[:50]}...", "success")
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
