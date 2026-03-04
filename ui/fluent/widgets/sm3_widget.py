"""
SM3 哈希算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel,
    InfoBar, MessageBox
)

from ui.fluent.components.algorithm_card import HashCard, LogCard
from core.algorithms.hash.SM3 import Thread as SM3Thread
from infrastructure.converters.TypeConvert import TypeConvert


class SM3Widget(ScrollArea):
    """SM3 哈希算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sm3Widget")
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
        title = TitleLabel("SM3 哈希")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "SM3 是中国国家密码管理局发布的密码哈希算法标准，"
            "输出256位哈希值，广泛应用于数字签名和消息认证。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 哈希卡片
        self.hashCard = HashCard()
        self.hashCard.inputEdit.setPlaceholderText("输入要哈希的消息...")
        layout.addWidget(self.hashCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("SM3 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.hashCard.hashBtn.clicked.connect(self.computeHash)
        self.hashCard.copyBtn.clicked.connect(self.copyHash)
        self.hashCard.clearBtn.clicked.connect(self.hashCard.clear)
    
    def computeHash(self):
        """计算哈希"""
        try:
            self.logCard.log("开始计算哈希...", "info")
            
            # 获取输入
            message = self.hashCard.getInput()
            if not message:
                raise ValueError("请输入消息")
            
            # 转换为字节列表
            message_bytes = message.encode('utf-8')
            message_list = list(message_bytes)
            
            self.logCard.log(f"消息: {message[:50]}{'...' if len(message) > 50 else ''}", "info")
            self.logCard.log(f"消息长度: {len(message_bytes)} 字节", "info")
            
            # 创建哈希线程
            thread = SM3Thread(self, message_list)
            thread.final_result.connect(self.onHashFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"哈希计算失败: {str(e)}", "error")
            MessageBox("错误", f"哈希计算失败: {str(e)}", self).exec()
    
    def onHashFinished(self, hash_value):
        """哈希计算完成"""
        self.hashCard.setHash(hash_value)
        self.logCard.log(f"哈希值: {hash_value}", "success")
        self.logCard.log("哈希计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content="SM3 哈希值已生成",
            parent=self
        )
    
    def copyHash(self):
        """复制哈希值"""
        from PyQt5.QtWidgets import QApplication
        hash_value = self.hashCard.getHash()
        QApplication.clipboard().setText(hash_value)
        InfoBar.success(title="已复制", content="哈希值已复制到剪贴板", parent=self)
        self.logCard.log("哈希值已复制到剪贴板", "info")
