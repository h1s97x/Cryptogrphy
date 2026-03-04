"""
Enigma 密码机界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, LineEdit,
    InfoBar, MessageBox, CardWidget, PushButton
)

from ui.components.algorithm_card import EncryptCard, DecryptCard, LogCard
from core.algorithms.classical.Enigma import Thread as EnigmaThread


class EnigmaConfigCard(CardWidget):
    """Enigma 配置卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("Enigma 配置")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 环设置
        ringLabel = BodyLabel("环设置 (Ring Setting):")
        layout.addWidget(ringLabel)
        
        self.ringEdit = LineEdit()
        self.ringEdit.setPlaceholderText("4个大写字母，例如: EPEL")
        self.ringEdit.setText("EPEL")
        layout.addWidget(self.ringEdit)
        
        # 起始位置
        posLabel = BodyLabel("起始位置 (Start Position):")
        layout.addWidget(posLabel)
        
        self.posEdit = LineEdit()
        self.posEdit.setPlaceholderText("4个大写字母，例如: CDSZ")
        self.posEdit.setText("CDSZ")
        layout.addWidget(self.posEdit)
        
        # 插线板
        plugLabel = BodyLabel("插线板 (Plugboard):")
        layout.addWidget(plugLabel)
        
        self.plugEdit = LineEdit()
        self.plugEdit.setPlaceholderText("字母对，用空格分隔，例如: AE BF CM DQ HU JN LX PR SZ VW")
        self.plugEdit.setText("AE BF CM DQ HU JN LX PR SZ VW")
        layout.addWidget(self.plugEdit)
        
        # 随机生成按钮
        self.generateBtn = PushButton("随机生成配置")
        layout.addWidget(self.generateBtn)
    
    def getRingSetting(self):
        """获取环设置"""
        return self.ringEdit.text().strip().upper()
    
    def getStartPosition(self):
        """获取起始位置"""
        return self.posEdit.text().strip().upper()
    
    def getPlugs(self):
        """获取插线板配置"""
        plug_text = self.plugEdit.text().strip().upper()
        if not plug_text:
            return []
        return plug_text.split()
    
    def setConfig(self, ring, pos, plugs):
        """设置配置"""
        self.ringEdit.setText(ring)
        self.posEdit.setText(pos)
        self.plugEdit.setText(' '.join(plugs))


class EnigmaWidget(ScrollArea):
    """Enigma 密码机界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("enigmaWidget")
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
        title = TitleLabel("Enigma 密码机")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "Enigma 是二战时期德国使用的著名密码机。"
            "本实现模拟 Enigma M4 型号，包含4个转子、反射器和插线板。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 配置卡片
        self.configCard = EnigmaConfigCard()
        layout.addWidget(self.configCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlaceholderText("输入明文（仅大写字母）...")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        self.decryptCard.ciphertextEdit.setPlaceholderText("输入密文（仅大写字母）...")
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("Enigma 密码机已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 配置卡片
        self.configCard.generateBtn.clicked.connect(self.generateConfig)
        
        # 加密卡片
        self.encryptCard.encryptBtn.clicked.connect(self.encrypt)
        self.encryptCard.copyBtn.clicked.connect(self.copyCiphertext)
        self.encryptCard.clearBtn.clicked.connect(self.encryptCard.clear)
        
        # 解密卡片
        self.decryptCard.decryptBtn.clicked.connect(self.decrypt)
        self.decryptCard.copyBtn.clicked.connect(self.copyPlaintext)
    
    def generateConfig(self):
        """生成随机配置"""
        import random
        import string
        
        # 生成随机环设置和起始位置
        ring = ''.join(random.choices(string.ascii_uppercase, k=4))
        pos = ''.join(random.choices(string.ascii_uppercase, k=4))
        
        # 生成随机插线板（10对）
        letters = list(string.ascii_uppercase)
        random.shuffle(letters)
        plugs = [letters[i] + letters[i+1] for i in range(0, 20, 2)]
        
        self.configCard.setConfig(ring, pos, plugs)
        self.logCard.log("已生成随机配置", "success")
        InfoBar.success(
            title="生成成功",
            content="已生成随机 Enigma 配置",
            parent=self
        )
    
    def validateConfig(self):
        """验证配置"""
        ring = self.configCard.getRingSetting()
        pos = self.configCard.getStartPosition()
        plugs = self.configCard.getPlugs()
        
        # 验证环设置
        if len(ring) != 4 or not ring.isalpha():
            raise ValueError("环设置必须是4个大写字母")
        
        # 验证起始位置
        if len(pos) != 4 or not pos.isalpha():
            raise ValueError("起始位置必须是4个大写字母")
        
        # 验证插线板
        if plugs:
            for plug in plugs:
                if len(plug) != 2 or not plug.isalpha():
                    raise ValueError(f"插线板配置错误: {plug}")
        
        return ring, pos, plugs
    
    def validateText(self, text, name):
        """验证文本"""
        if not text:
            raise ValueError(f"请输入{name}")
        
        # 只保留大写字母
        text = ''.join(c for c in text.upper() if c.isalpha())
        
        if not text:
            raise ValueError(f"{name}必须包含字母")
        
        return text
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 验证配置
            ring, pos, plugs = self.validateConfig()
            
            # 验证明文
            plaintext = self.encryptCard.getPlaintext()
            plaintext = self.validateText(plaintext, "明文")
            
            self.encryptCard.setPlaintext(plaintext)
            
            self.logCard.log(f"明文: {plaintext}", "info")
            self.logCard.log(f"环设置: {ring}", "info")
            self.logCard.log(f"起始位置: {pos}", "info")
            
            # 创建加密线程
            thread = EnigmaThread(self, ring, pos, plugs, plaintext, 0)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
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
    
    def decrypt(self):
        """解密"""
        try:
            self.logCard.log("开始解密...", "info")
            
            # 验证配置
            ring, pos, plugs = self.validateConfig()
            
            # 验证密文
            ciphertext = self.decryptCard.getCiphertext()
            ciphertext = self.validateText(ciphertext, "密文")
            
            self.decryptCard.setCiphertext(ciphertext)
            
            self.logCard.log(f"密文: {ciphertext}", "info")
            self.logCard.log(f"环设置: {ring}", "info")
            self.logCard.log(f"起始位置: {pos}", "info")
            
            # 创建解密线程
            thread = EnigmaThread(self, ring, pos, plugs, ciphertext, 1)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
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
