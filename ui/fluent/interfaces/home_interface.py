"""
首页界面
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGridLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    FluentIcon as FIF, IconWidget
)


class StatCard(CardWidget):
    """统计卡片"""
    
    def __init__(self, icon, title, value, parent=None):
        super().__init__(parent)
        self.initUI(icon, title, value)
    
    def initUI(self, icon, title, value):
        layout = QHBoxLayout(self)
        
        # 图标
        iconWidget = IconWidget(icon, self)
        iconWidget.setFixedSize(48, 48)
        layout.addWidget(iconWidget)
        
        # 文本
        textLayout = QVBoxLayout()
        titleLabel = BodyLabel(title)
        valueLabel = TitleLabel(str(value))
        textLayout.addWidget(titleLabel)
        textLayout.addWidget(valueLabel)
        
        layout.addLayout(textLayout)
        layout.addStretch()


class HomeInterface(ScrollArea):
    """首页界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("homeInterface")
        self.initUI()
    
    def initUI(self):
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(24)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        title = TitleLabel("欢迎使用密码学平台")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "这是一个集成了多种密码算法的教学和实验平台，"
            "包括经典密码、分组密码、公钥密码、哈希算法等。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 统计卡片
        statsLayout = QGridLayout()
        statsLayout.setSpacing(16)
        
        stats = [
            (FIF.FONT, "经典密码", 7),
            (FIF.FINGERPRINT, "分组密码", 6),
            (FIF.CERTIFICATE, "公钥密码", 7),
            (FIF.TAG, "哈希算法", 9),
            (FIF.SYNC, "流密码", 4),
            (FIF.LABEL, "数学基础", 3),
        ]
        
        for i, (icon, title, count) in enumerate(stats):
            card = StatCard(icon, title, count)
            statsLayout.addWidget(card, i // 3, i % 3)
        
        layout.addLayout(statsLayout)
        
        # 快速开始
        quickStartCard = CardWidget()
        quickStartLayout = QVBoxLayout(quickStartCard)
        
        quickTitle = TitleLabel("快速开始")
        quickStartLayout.addWidget(quickTitle)
        
        quickDesc = BodyLabel(
            "1. 从左侧导航栏选择一个算法\n"
            "2. 配置密钥参数\n"
            "3. 输入明文或密文\n"
            "4. 点击加密或解密按钮\n"
            "5. 查看结果和日志"
        )
        quickStartLayout.addWidget(quickDesc)
        
        layout.addWidget(quickStartCard)
        
        layout.addStretch()
