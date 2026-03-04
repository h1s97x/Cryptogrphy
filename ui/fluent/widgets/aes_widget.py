"""
AES 算法界面 - Fluent Design 版本
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import ScrollArea, TitleLabel, BodyLabel


class AESWidget(ScrollArea):
    """AES 算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("aesWidget")
        self.initUI()
    
    def initUI(self):
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setContentsMargins(36, 36, 36, 36)
        
        title = TitleLabel("AES 加密")
        layout.addWidget(title)
        
        desc = BodyLabel("AES算法界面开发中...")
        layout.addWidget(desc)
        
        layout.addStretch()
