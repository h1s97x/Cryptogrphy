"""
AES-CBC-MAC 消息认证码算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, TextEdit, PrimaryPushButton,
    FluentIcon as FIF
)

from ui.components.algorithm_card import LogCard
from core.algorithms.hash.AES_CBC_MAC import Thread as AESCBCMACThread
from infrastructure.converters import TypeConvert


class AESCBCMACCard(CardWidget):
    """AES-CBC-MAC计算卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("🔐 AES-CBC-MAC 计算")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 密钥输入
        keyLabel = BodyLabel("密钥 (128位)")
        layout.addWidget(keyLabel)
        
        self.keyEdit = TextEdit()
        self.keyEdit.setPlaceholderText("输入128位密钥（十六进制）...")
        self.keyEdit.setMaximumHeight(60)
        layout.addWidget(self.keyEdit)
        
        # 消息输入
        messageLabel = BodyLabel("消息 (128位的倍数)")
        layout.addWidget(messageLabel)
        
        self.messageEdit = TextEdit()
        self.messageEdit.setPlaceholderText("输入消息（十六进制，长度必须是128位的倍数）...")
        self.messageEdit.setMaximumHeight(100)
        layout.addWidget(self.messageEdit)
        
        # MAC输出
        macLabel = BodyLabel("MAC值")
        layout.addWidget(macLabel)
        
        self.macEdit = TextEdit()
        self.macEdit.setPlaceholderText("MAC结果将显示在这里")
        self.macEdit.setReadOnly(True)
        self.macEdit.setMaximumHeight(60)
        layout.addWidget(self.macEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.computeBtn = PrimaryPushButton(FIF.FINGERPRINT, "计算MAC")
        self.generateKeyBtn = PushButton(FIF.SYNC, "生成密钥")
        self.copyBtn = PushButton(FIF.COPY, "复制MAC")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.computeBtn)
        btnLayout.addWidget(self.generateKeyBtn)
        btnLayout.addWidget(self.copyBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getKey(self):
        """获取密钥"""
        return self.keyEdit.toPlainText()
    
    def setKey(self, text):
        """设置密钥"""
        self.keyEdit.setPlainText(text)
    
    def getMessage(self):
        """获取消息"""
        return self.messageEdit.toPlainText()
    
    def setMessage(self, text):
        """设置消息"""
        self.messageEdit.setPlainText(text)
    
    def getMAC(self):
        """获取MAC"""
        return self.macEdit.toPlainText()
    
    def setMAC(self, text):
        """设置MAC"""
        self.macEdit.setPlainText(text)
    
    def clear(self):
        """清空"""
        self.macEdit.clear()


class AESCBCMACWidget(ScrollArea):
    """AES-CBC-MAC 消息认证码算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("aesCbcMacWidget")
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
        title = TitleLabel("AES-CBC-MAC")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "AES-CBC-MAC 是基于 AES-CBC 模式的消息认证码算法。"
            "使用128位密钥，消息长度必须是128位（16字节）的倍数。"
            "输出最后一个密文块作为MAC值。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # AES-CBC-MAC卡片
        self.macCard = AESCBCMACCard()
        # 设置默认值
        self.macCard.setKey("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C")
        self.macCard.setMessage("32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 " +
                               "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00")
        layout.addWidget(self.macCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("AES-CBC-MAC 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.macCard.computeBtn.clicked.connect(self.computeMAC)
        self.macCard.generateKeyBtn.clicked.connect(self.generateKey)
        self.macCard.copyBtn.clicked.connect(self.copyMAC)
        self.macCard.clearBtn.clicked.connect(self.macCard.clear)
    
    def generateKey(self):
        """生成密钥"""
        import os
        key_bytes = os.urandom(16)
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.macCard.setKey(key_hex)
        self.logCard.log(f"已生成随机密钥", "success")
        InfoBar.success(
            title="生成成功",
            content="已生成128位随机密钥",
            parent=self
        )
    
    def validateHexInput(self, text, name, expected_length=None):
        """验证十六进制输入"""
        try:
            hex_list = TypeConvert.str_to_hex_list(text)
            
            if hex_list == 'ERROR_CHARACTER':
                raise ValueError(f"{name}包含非法字符，只能包含十六进制字符（0-9, A-F）")
            
            if hex_list == 'ERROR_LENGTH':
                raise ValueError(f"{name}长度必须是2的倍数")
            
            if hex_list is None:
                raise ValueError(f"{name}格式错误")
            
            if expected_length and len(hex_list) != expected_length:
                raise ValueError(f"{name}长度必须是{expected_length}字节，当前长度为{len(hex_list)}字节")
            
            return True, hex_list
        except Exception as e:
            return False, str(e)
    
    def computeMAC(self):
        """计算MAC"""
        try:
            self.logCard.log("开始计算MAC...", "info")
            
            # 验证密钥
            key_text = self.macCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            
            # 验证消息
            message_text = self.macCard.getMessage()
            valid, result = self.validateHexInput(message_text, "消息")
            if not valid:
                raise ValueError(result)
            
            message_len = len(result)
            
            # 检查消息长度是否是16的倍数
            if message_len % 16 != 0:
                raise ValueError(f"消息长度必须是16字节的倍数，当前长度为{message_len}字节")
            
            # 转换为整数
            message = TypeConvert.str_to_int(message_text)
            key = key_text
            
            # 格式化显示
            message_formatted = TypeConvert.int_to_str(message, message_len)
            self.macCard.setMessage(message_formatted)
            
            self.logCard.log(f"密钥: {key}", "info")
            self.logCard.log(f"消息: {message_formatted[:50]}...", "info")
            self.logCard.log(f"消息长度: {message_len} 字节 ({message_len // 16} 块)", "info")
            
            # 创建MAC计算线程
            thread = AESCBCMACThread(self, message, message_len, key)
            thread.intermediate_value.connect(self.onIntermediateValue)
            thread.final_result.connect(self.onMACFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算MAC失败: {str(e)}", "error")
            MessageBox("错误", f"计算MAC失败: {str(e)}", self).exec()
    
    def onIntermediateValue(self, text):
        """中间值输出"""
        self.logCard.log(text, "info")
    
    def onMACFinished(self, mac_value):
        """MAC计算完成"""
        self.macCard.setMAC(mac_value)
        self.logCard.log(f"MAC值: {mac_value}", "success")
        self.logCard.log("MAC计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content="MAC值已生成",
            parent=self
        )
    
    def copyMAC(self):
        """复制MAC值"""
        from PyQt5.QtWidgets import QApplication
        mac_value = self.macCard.getMAC()
        if mac_value:
            QApplication.clipboard().setText(mac_value)
            InfoBar.success(title="已复制", content="MAC值已复制到剪贴板", parent=self)
            self.logCard.log("MAC值已复制到剪贴板", "info")
        else:
            InfoBar.warning(title="提示", content="没有可复制的MAC值", parent=self)
