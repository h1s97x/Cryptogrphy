"""
AES 分组模式算法界面 - Fluent Design 版本
支持 ECB 和 CBC 模式
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, TextEdit, PrimaryPushButton,
    ComboBox, SpinBox, FluentIcon as FIF
)

from ui.components.algorithm_card import LogCard
from core.algorithms.symmetric.Block_Mode import Thread as BlockModeThread
from infrastructure.converters import TypeConvert


class BlockModeCard(CardWidget):
    """分组模式卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("🔐 AES 分组模式")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 模式选择
        modeLabel = BodyLabel("加密模式")
        layout.addWidget(modeLabel)
        
        self.modeCombo = ComboBox()
        self.modeCombo.addItems(["ECB (电子密码本)", "CBC (密码分组链接)"])
        self.modeCombo.setCurrentIndex(0)
        layout.addWidget(self.modeCombo)
        
        # 分组数量
        blockLabel = BodyLabel("分组数量 (每组16字节)")
        layout.addWidget(blockLabel)
        
        self.blockSpin = SpinBox()
        self.blockSpin.setRange(1, 10)
        self.blockSpin.setValue(2)
        layout.addWidget(self.blockSpin)
        
        # 密钥输入
        keyLabel = BodyLabel("密钥 (128位)")
        layout.addWidget(keyLabel)
        
        self.keyEdit = TextEdit()
        self.keyEdit.setPlaceholderText("输入128位密钥（十六进制）...")
        self.keyEdit.setMaximumHeight(60)
        layout.addWidget(self.keyEdit)
        
        # 明文/密文输入
        inputLabel = BodyLabel("输入数据")
        layout.addWidget(inputLabel)
        
        self.inputEdit = TextEdit()
        self.inputEdit.setPlaceholderText("输入数据（十六进制，长度为16字节的倍数）...")
        self.inputEdit.setMaximumHeight(100)
        layout.addWidget(self.inputEdit)
        
        # 输出
        outputLabel = BodyLabel("输出数据")
        layout.addWidget(outputLabel)
        
        self.outputEdit = TextEdit()
        self.outputEdit.setPlaceholderText("输出结果将显示在这里")
        self.outputEdit.setReadOnly(True)
        self.outputEdit.setMaximumHeight(100)
        layout.addWidget(self.outputEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.encryptBtn = PrimaryPushButton(FIF.SEND, "加密")
        self.decryptBtn = PrimaryPushButton(FIF.ACCEPT, "解密")
        self.generateKeyBtn = PushButton(FIF.SYNC, "生成密钥")
        self.copyBtn = PushButton(FIF.COPY, "复制")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.encryptBtn)
        btnLayout.addWidget(self.decryptBtn)
        btnLayout.addWidget(self.generateKeyBtn)
        btnLayout.addWidget(self.copyBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getMode(self):
        """获取模式"""
        return self.modeCombo.currentIndex()
    
    def getBlockCount(self):
        """获取分组数量"""
        return self.blockSpin.value()
    
    def getKey(self):
        """获取密钥"""
        return self.keyEdit.toPlainText()
    
    def setKey(self, text):
        """设置密钥"""
        self.keyEdit.setPlainText(text)
    
    def getInput(self):
        """获取输入"""
        return self.inputEdit.toPlainText()
    
    def setInput(self, text):
        """设置输入"""
        self.inputEdit.setPlainText(text)
    
    def getOutput(self):
        """获取输出"""
        return self.outputEdit.toPlainText()
    
    def setOutput(self, text):
        """设置输出"""
        self.outputEdit.setPlainText(text)
    
    def clear(self):
        """清空"""
        self.outputEdit.clear()


class BlockModeWidget(ScrollArea):
    """AES 分组模式算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("blockModeWidget")
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
        title = TitleLabel("AES 分组模式")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "AES 分组模式支持 ECB 和 CBC 两种模式：\n"
            "• ECB (电子密码本) - 每个分组独立加密，相同明文产生相同密文\n"
            "• CBC (密码分组链接) - 使用初始向量 IV，每个分组与前一个密文异或后加密\n"
            "密钥长度为128位，数据长度必须是16字节的倍数。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 分组模式卡片
        self.modeCard = BlockModeCard()
        # 设置默认值
        self.modeCard.setKey("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C")
        self.modeCard.setInput("32 43 F6 A8 88 5A 30 8D 31 31 98 A2 E0 37 07 34 " +
                              "11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00")
        layout.addWidget(self.modeCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("AES 分组模式算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.modeCard.encryptBtn.clicked.connect(self.encrypt)
        self.modeCard.decryptBtn.clicked.connect(self.decrypt)
        self.modeCard.generateKeyBtn.clicked.connect(self.generateKey)
        self.modeCard.copyBtn.clicked.connect(self.copyOutput)
        self.modeCard.clearBtn.clicked.connect(self.modeCard.clear)
    
    def generateKey(self):
        """生成密钥"""
        import os
        key_bytes = os.urandom(16)
        key_hex = ' '.join([f'{b:02X}' for b in key_bytes])
        self.modeCard.setKey(key_hex)
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
    
    def encrypt(self):
        """加密"""
        try:
            mode = self.modeCard.getMode()
            mode_name = "ECB" if mode == 0 else "CBC"
            block_count = self.modeCard.getBlockCount()
            
            self.logCard.log(f"开始{mode_name}加密...", "info")
            
            # 验证密钥
            key_text = self.modeCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            
            # 验证输入
            input_text = self.modeCard.getInput()
            valid, result = self.validateHexInput(input_text, "明文")
            if not valid:
                raise ValueError(result)
            
            input_len = len(result)
            
            # 检查长度是否是16的倍数
            if input_len % 16 != 0:
                raise ValueError(f"明文长度必须是16字节的倍数，当前长度为{input_len}字节")
            
            # 转换为整数
            input_int = TypeConvert.str_to_int(input_text)
            
            # 格式化显示
            input_formatted = TypeConvert.int_to_str(input_int, input_len)
            self.modeCard.setInput(input_formatted)
            
            self.logCard.log(f"模式: {mode_name}", "info")
            self.logCard.log(f"密钥: {key_text}", "info")
            self.logCard.log(f"明文: {input_formatted[:50]}...", "info")
            self.logCard.log(f"分组数: {input_len // 16}", "info")
            
            # 创建加密线程
            thread = BlockModeThread(self, input_formatted, key_text, mode, 0, input_len)
            thread.intermediate_value.connect(self.onIntermediateValue)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def decrypt(self):
        """解密"""
        try:
            mode = self.modeCard.getMode()
            mode_name = "ECB" if mode == 0 else "CBC"
            
            self.logCard.log(f"开始{mode_name}解密...", "info")
            
            # 验证密钥
            key_text = self.modeCard.getKey()
            valid, result = self.validateHexInput(key_text, "密钥", 16)
            if not valid:
                raise ValueError(result)
            
            # 验证输入
            input_text = self.modeCard.getInput()
            valid, result = self.validateHexInput(input_text, "密文")
            if not valid:
                raise ValueError(result)
            
            input_len = len(result)
            
            # 检查长度是否是16的倍数
            if input_len % 16 != 0:
                raise ValueError(f"密文长度必须是16字节的倍数，当前长度为{input_len}字节")
            
            # 转换为整数
            input_int = TypeConvert.str_to_int(input_text)
            
            # 格式化显示
            input_formatted = TypeConvert.int_to_str(input_int, input_len)
            self.modeCard.setInput(input_formatted)
            
            self.logCard.log(f"模式: {mode_name}", "info")
            self.logCard.log(f"密钥: {key_text}", "info")
            self.logCard.log(f"密文: {input_formatted[:50]}...", "info")
            self.logCard.log(f"分组数: {input_len // 16}", "info")
            
            # 创建解密线程
            thread = BlockModeThread(self, input_formatted, key_text, mode, 1, input_len)
            thread.intermediate_value.connect(self.onIntermediateValue)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onIntermediateValue(self, text):
        """中间值输出"""
        self.logCard.log(text, "info")
    
    def onEncryptFinished(self, ciphertext):
        """加密完成"""
        self.modeCard.setOutput(ciphertext)
        self.logCard.log(f"密文: {ciphertext[:50]}...", "success")
        self.logCard.log("加密完成", "success")
        
        InfoBar.success(
            title="加密成功",
            content="明文已成功加密",
            parent=self
        )
    
    def onDecryptFinished(self, plaintext):
        """解密完成"""
        self.modeCard.setOutput(plaintext)
        self.logCard.log(f"明文: {plaintext[:50]}...", "success")
        self.logCard.log("解密完成", "success")
        
        InfoBar.success(
            title="解密成功",
            content="密文已成功解密",
            parent=self
        )
    
    def copyOutput(self):
        """复制输出"""
        from PyQt5.QtWidgets import QApplication
        output = self.modeCard.getOutput()
        if output:
            QApplication.clipboard().setText(output)
            InfoBar.success(title="已复制", content="输出已复制到剪贴板", parent=self)
            self.logCard.log("输出已复制到剪贴板", "info")
        else:
            InfoBar.warning(title="提示", content="没有可复制的输出", parent=self)
