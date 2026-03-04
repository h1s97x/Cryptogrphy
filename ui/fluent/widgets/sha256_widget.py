"""
SHA-256 算法界面 - Fluent Design 版本
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import ScrollArea, TitleLabel, BodyLabel


class SHA256Widget(ScrollArea):
    """SHA-256 算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sha256Widget")
        self.initUI()
    
    def initUI(self):
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setContentsMargins(36, 36, 36, 36)
        
        title = TitleLabel("SHA-256 哈希")
        layout.addWidget(title)
        
        desc = BodyLabel("SHA-256算法界面开发中...")
        layout.addWidget(desc)
        
        layout.addStretch()
