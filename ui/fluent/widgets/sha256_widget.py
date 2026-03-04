"""
SHA-256 哈希算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel,
    InfoBar, MessageBox
)

from ui.fluent.components.algorithm_card import HashCard, LogCard
from core.algorithms.hash.SHA256 import Thread as SHA256Thread
from infrastructure.converters import TypeConvert


class SHA256Widget(ScrollArea):
    """SHA-256 哈希算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sha256Widget")
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
        title = TitleLabel("SHA-256 哈希")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "SHA-256 (Secure Hash Algorithm 256-bit) 是一种密码学哈希函数，"
            "可以将任意长度的消息转换为固定长度（256位）的哈希值。输入格式为十六进制。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 哈希卡片
        self.hashCard = HashCard()
        self.hashCard.messageEdit.setPlainText("61 62 63")
        self.hashCard.messageEdit.setPlaceholderText("输入消息（十六进制）...")
        layout.addWidget(self.hashCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("SHA-256 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.hashCard.hashBtn.clicked.connect(self.computeHash)
        self.hashCard.copyBtn.clicked.connect(self.copyHash)
        self.hashCard.clearBtn.clicked.connect(self.hashCard.clear)
    
    def validateHexInput(self, text, name):
        """验证十六进制输入"""
        try:
            hex_list = TypeConvert.str_to_hex_list(text)
            
            if hex_list == 'ERROR_CHARACTER':
                raise ValueError(f"{name}包含非法字符，只能包含十六进制字符（0-9, A-F）")
            
            if hex_list == 'ERROR_LENGTH':
                raise ValueError(f"{name}长度必须是2的倍数")
            
            if hex_list is None:
                raise ValueError(f"{name}格式错误")
            
            if len(hex_list) == 0:
                raise ValueError(f"{name}不能为空")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def computeHash(self):
        """计算哈希"""
        try:
            self.logCard.log("开始计算哈希...", "info")
            
            # 验证消息
            message_text = self.hashCard.getMessage()
            valid, result = self.validateHexInput(message_text, "消息")
            if not valid:
                raise ValueError(result)
            
            message_len = len(result)
            
            # 转换为整数
            message = TypeConvert.str_to_int(message_text)
            
            # 格式化显示
            message_formatted = TypeConvert.int_to_str(message, message_len)
            self.hashCard.setMessage(message_formatted)
            
            self.logCard.log(f"消息: {message_formatted}", "info")
            self.logCard.log(f"消息长度: {message_len} 字节", "info")
            
            # 创建哈希线程
            thread = SHA256Thread(self, message, message_len)
            thread.final_result.connect(self.onHashFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算哈希失败: {str(e)}", "error")
            MessageBox("错误", f"计算哈希失败: {str(e)}", self).exec()
    
    def onHashFinished(self, hash_value):
        """哈希计算完成"""
        self.hashCard.setHash(hash_value)
        self.logCard.log(f"哈希值: {hash_value}", "success")
        self.logCard.log("哈希计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content="哈希值已生成",
            parent=self
        )
    
    def copyHash(self):
        """复制哈希值"""
        from PyQt5.QtWidgets import QApplication
        hash_value = self.hashCard.getHash()
        if hash_value:
            QApplication.clipboard().setText(hash_value)
            InfoBar.success(title="已复制", content="哈希值已复制到剪贴板", parent=self)
            self.logCard.log("哈希值已复制到剪贴板", "info")
        else:
            InfoBar.warning(title="提示", content="没有可复制的哈希值", parent=self)
