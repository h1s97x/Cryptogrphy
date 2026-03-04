"""
HMAC-MD5 消息认证码界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, PlainTextEdit,
    InfoBar, MessageBox, CardWidget, PushButton
)

from ui.fluent.components.algorithm_card import LogCard
from core.algorithms.hash.HMAC_MD5 import Thread as HMACThread
from infrastructure.converters import TypeConvert


class HMACInputCard(CardWidget):
    """HMAC输入卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("输入")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 密钥
        keyLabel = BodyLabel("密钥 (十六进制):")
        layout.addWidget(keyLabel)
        
        self.keyEdit = PlainTextEdit()
        self.keyEdit.setPlaceholderText("输入密钥（十六进制）...")
        self.keyEdit.setPlainText("0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B")
        self.keyEdit.setMaximumHeight(80)
        layout.addWidget(self.keyEdit)
        
        # 消息
        msgLabel = BodyLabel("消息 (十六进制):")
        layout.addWidget(msgLabel)
        
        self.msgEdit = PlainTextEdit()
        self.msgEdit.setPlaceholderText("输入消息（十六进制）...")
        self.msgEdit.setPlainText("48 69 20 54 68 65 72 65")  # "Hi There"
        self.msgEdit.setMaximumHeight(80)
        layout.addWidget(self.msgEdit)
        
        # 生成按钮
        self.generateBtn = PushButton("生成随机密钥")
        layout.addWidget(self.generateBtn)


class HMACResultCard(CardWidget):
    """HMAC结果卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("HMAC-MD5 结果")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 结果
        resultLabel = BodyLabel("HMAC值:")
        layout.addWidget(resultLabel)
        
        self.resultEdit = PlainTextEdit()
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setPlaceholderText("HMAC结果将显示在这里...")
        self.resultEdit.setMaximumHeight(80)
        layout.addWidget(self.resultEdit)
        
        # 按钮
        btnLayout = QVBoxLayout()
        btnLayout.setSpacing(8)
        
        self.computeBtn = PushButton("计算 HMAC")
        btnLayout.addWidget(self.computeBtn)
        
        self.copyBtn = PushButton("复制结果")
        btnLayout.addWidget(self.copyBtn)
        
        layout.addLayout(btnLayout)


class HMACMD5Widget(ScrollArea):
    """HMAC-MD5 消息认证码界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("hmacmd5Widget")
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
        title = TitleLabel("HMAC-MD5 消息认证码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "HMAC (Hash-based Message Authentication Code) 是一种基于哈希函数的消息认证码。"
            "HMAC-MD5 使用MD5作为底层哈希函数，结合密钥对消息进行认证。"
            "输出128位认证码。输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 输入卡片
        self.inputCard = HMACInputCard()
        layout.addWidget(self.inputCard)
        
        # 结果卡片
        self.resultCard = HMACResultCard()
        layout.addWidget(self.resultCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("HMAC-MD5 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.inputCard.generateBtn.clicked.connect(self.generateKey)
        self.resultCard.computeBtn.clicked.connect(self.computeHMAC)
        self.resultCard.copyBtn.clicked.connect(self.copyResult)
    
    def generateKey(self):
        """生成随机密钥"""
        import os
        key_bytes = os.urandom(16)
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.inputCard.keyEdit.setPlainText(key_hex)
        self.logCard.log("已生成随机密钥", "success")
        InfoBar.success(
            title="生成成功",
            content="已生成128位随机密钥",
            parent=self
        )
    
    def validateHexInput(self, text, name):
        """验证十六进制输入"""
        try:
            hex_list = TypeConvert.str_to_hex_list(text)
            
            if hex_list is None or hex_list == 'ERROR_CHARACTER' or hex_list == 'ERROR_LENGTH':
                raise ValueError(f"{name}格式错误")
            
            if len(hex_list) == 0:
                raise ValueError(f"{name}不能为空")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def computeHMAC(self):
        """计算HMAC"""
        try:
            self.logCard.log("开始计算HMAC...", "info")
            
            # 验证密钥
            key_text = self.inputCard.keyEdit.toPlainText().strip()
            valid, result = self.validateHexInput(key_text, "密钥")
            if not valid:
                raise ValueError(result)
            key_list = result
            key_len = len(key_list)
            
            # 验证消息
            msg_text = self.inputCard.msgEdit.toPlainText().strip()
            valid, result = self.validateHexInput(msg_text, "消息")
            if not valid:
                raise ValueError(result)
            msg_list = result
            msg_len = len(msg_list)
            
            # 转换为整数
            key_int = TypeConvert.hex_list_to_int(key_list)
            msg_int = TypeConvert.hex_list_to_int(msg_list)
            
            self.logCard.log(f"密钥长度: {key_len} 字节", "info")
            self.logCard.log(f"消息长度: {msg_len} 字节", "info")
            
            # 创建HMAC线程
            thread = HMACThread(self, msg_int, msg_len, key_int, key_len)
            thread.final_result.connect(self.onHMACFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算失败: {str(e)}", "error")
            MessageBox("错误", f"计算失败: {str(e)}", self).exec()
    
    def onHMACFinished(self, hmac_value):
        """HMAC计算完成"""
        self.resultCard.resultEdit.setPlainText(hmac_value)
        self.logCard.log(f"HMAC: {hmac_value}", "success")
        self.logCard.log("计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content="HMAC-MD5 已生成",
            parent=self
        )
    
    def copyResult(self):
        """复制结果"""
        from PyQt5.QtWidgets import QApplication
        result = self.resultCard.resultEdit.toPlainText()
        if not result:
            InfoBar.warning(title="提示", content="没有可复制的结果", parent=self)
            return
        
        QApplication.clipboard().setText(result)
        InfoBar.success(title="已复制", content="HMAC值已复制到剪贴板", parent=self)
        self.logCard.log("HMAC值已复制到剪贴板", "info")
