"""
Vigenere 密码算法界面 - Fluent Design 版本
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import ScrollArea, TitleLabel, BodyLabel


class VigenereWidget(ScrollArea):
    """Vigenere 密码算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("vigenereWidget")
        self.initUI()
    
    def initUI(self):
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setContentsMargins(36, 36, 36, 36)
        
        title = TitleLabel("Vigenere 密码")
        layout.addWidget(title)
        
        desc = BodyLabel("Vigenere密码界面开发中...")
        layout.addWidget(desc)
        
        layout.addStretch()
