"""
分类界面 - 显示某一类算法的列表
"""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QGridLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    FluentIcon as FIF, IconWidget, PushButton
)


class AlgorithmCard(CardWidget):
    """算法卡片"""
    
    clicked = pyqtSignal(str)  # 点击信号，传递算法名称
    
    def __init__(self, icon, name, description, objectName, parent=None):
        super().__init__(parent)
        self.objectName = objectName
        self.initUI(icon, name, description)
    
    def initUI(self, icon, name, description):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 图标
        iconWidget = IconWidget(icon, self)
        iconWidget.setFixedSize(48, 48)
        layout.addWidget(iconWidget, alignment=Qt.AlignCenter)
        
        # 名称
        nameLabel = TitleLabel(name)
        nameLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(nameLabel)
        
        # 描述
        descLabel = BodyLabel(description)
        descLabel.setWordWrap(True)
        descLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(descLabel)
        
        # 按钮
        self.openBtn = PushButton("打开")
        self.openBtn.clicked.connect(lambda: self.clicked.emit(self.objectName))
        layout.addWidget(self.openBtn)
        
        self.setFixedHeight(200)


class CategoryInterface(ScrollArea):
    """分类界面"""
    
    algorithmClicked = pyqtSignal(str)  # 算法点击信号
    
    def __init__(self, title, description, algorithms, parent=None):
        super().__init__(parent)
        self.title = title
        self.description = description
        self.algorithms = algorithms
        self.initUI()
    
    def initUI(self):
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(24)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        titleLabel = TitleLabel(self.title)
        layout.addWidget(titleLabel)
        
        # 描述
        descLabel = BodyLabel(self.description)
        descLabel.setWordWrap(True)
        layout.addWidget(descLabel)
        
        # 算法卡片网格
        gridLayout = QGridLayout()
        gridLayout.setSpacing(16)
        
        for i, algo in enumerate(self.algorithms):
            card = AlgorithmCard(
                algo['icon'],
                algo['name'],
                algo['description'],
                algo['objectName']
            )
            card.clicked.connect(self.algorithmClicked.emit)
            gridLayout.addWidget(card, i // 3, i % 3)
        
        layout.addLayout(gridLayout)
        layout.addStretch()
