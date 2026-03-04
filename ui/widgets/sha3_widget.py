"""
SHA-3 哈希算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel,
    InfoBar, MessageBox, ComboBox
)

from ui.components.algorithm_card import HashCard, LogCard
from core.algorithms.hash.SHA3 import Thread as SHA3Thread


class SHA3Widget(ScrollArea):
    """SHA-3 哈希算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sha3Widget")
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
        title = TitleLabel("SHA-3 哈希")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "SHA-3 是最新的安全哈希算法标准，基于Keccak算法。"
            "支持多种输出长度：224、256、384、512位。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 输出长度选择
        lengthWidget = QWidget()
        lengthLayout = QVBoxLayout(lengthWidget)
        lengthLayout.setContentsMargins(0, 0, 0, 0)
        
        lengthLabel = BodyLabel("输出长度:")
        lengthLayout.addWidget(lengthLabel)
        
        self.lengthCombo = ComboBox()
        self.lengthCombo.addItems(["224", "256", "384", "512"])
        self.lengthCombo.setCurrentIndex(1)  # 默认256
        self.lengthCombo.setFixedWidth(200)
        lengthLayout.addWidget(self.lengthCombo)
        
        layout.addWidget(lengthWidget)
        
        # 哈希卡片
        self.hashCard = HashCard()
        self.hashCard.messageEdit.setPlaceholderText("输入要哈希的消息...")
        layout.addWidget(self.hashCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("SHA-3 算法已加载", "success")
    
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
            message = self.hashCard.getMessage()
            if not message:
                raise ValueError("请输入消息")
            
            # 获取输出长度
            output_length = int(self.lengthCombo.currentText())
            
            self.logCard.log(f"消息: {message[:50]}{'...' if len(message) > 50 else ''}", "info")
            self.logCard.log(f"输出长度: {output_length} 位", "info")
            
            # 创建哈希线程
            # SHA3 Thread 参数: parent, message, d (output bits), l (log2(lane size))
            # d = output_length, l = 6 (默认值，对应64位lane)
            thread = SHA3Thread(self, message, output_length, 6)
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
            content="SHA-3 哈希值已生成",
            parent=self
        )
    
    def copyHash(self):
        """复制哈希值"""
        from PyQt5.QtWidgets import QApplication
        hash_value = self.hashCard.getHash()
        QApplication.clipboard().setText(hash_value)
        InfoBar.success(title="已复制", content="哈希值已复制到剪贴板", parent=self)
        self.logCard.log("哈希值已复制到剪贴板", "info")
