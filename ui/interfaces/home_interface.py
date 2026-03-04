"""
首页界面 - 显示算法分类导航
"""

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QGridLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    FluentIcon as FIF, IconWidget, PrimaryPushButton
)


class CategoryCard(CardWidget):
    """分类卡片"""
    
    categoryClicked = pyqtSignal(str)  # 点击信号，传递分类名称
    
    def __init__(self, icon, title, count, description, category, parent=None):
        super().__init__(parent)
        self.category = category
        self.initUI(icon, title, count, description)
    
    def initUI(self, icon, title, count, description):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        
        # 图标
        iconWidget = IconWidget(icon, self)
        iconWidget.setFixedSize(64, 64)
        layout.addWidget(iconWidget, alignment=Qt.AlignCenter)
        
        # 标题和数量
        titleLabel = TitleLabel(f"{title} ({count})")
        titleLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(titleLabel)
        
        # 描述
        descLabel = BodyLabel(description)
        descLabel.setWordWrap(True)
        descLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(descLabel)
        
        # 按钮
        self.openBtn = PrimaryPushButton("查看算法")
        self.openBtn.clicked.connect(lambda: self.categoryClicked.emit(self.category))
        layout.addWidget(self.openBtn)
        
        self.setFixedHeight(260)


class HomeInterface(ScrollArea):
    """首页界面"""
    
    categoryClicked = pyqtSignal(str)  # 分类点击信号
    
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
            "这是一个集成了多种密码算法的教学和实验平台。"
            "选择下方的分类，探索不同类型的密码学算法。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 分类卡片
        categoriesLayout = QGridLayout()
        categoriesLayout.setSpacing(20)
        
        categories = [
            {
                'icon': FIF.FONT,
                'title': '经典密码',
                'count': 7,
                'description': 'Caesar、Hill、Vigenere、Playfair、Enigma等古典加密算法',
                'category': 'classical'
            },
            {
                'icon': FIF.FINGERPRINT,
                'title': '对称密码',
                'count': 8,
                'description': 'AES、DES、SM4等现代分组密码和流密码算法',
                'category': 'symmetric'
            },
            {
                'icon': FIF.CERTIFICATE,
                'title': '公钥密码',
                'count': 4,
                'description': 'RSA、ElGamal、ECDSA等非对称加密和数字签名',
                'category': 'asymmetric'
            },
            {
                'icon': FIF.TAG,
                'title': '哈希算法',
                'count': 7,
                'description': 'MD5、SHA系列、SM3等消息摘要和MAC算法',
                'category': 'hash'
            },
            {
                'icon': FIF.EDIT,
                'title': '数学基础',
                'count': 3,
                'description': 'Euler定理、中国剩余定理、欧几里得算法',
                'category': 'mathematical'
            },
            {
                'icon': FIF.LINK,
                'title': '密码协议',
                'count': 2,
                'description': '重放攻击、Verify验证协议等安全协议演示',
                'category': 'protocols'
            },
        ]
        
        for i, cat in enumerate(categories):
            card = CategoryCard(
                cat['icon'],
                cat['title'],
                cat['count'],
                cat['description'],
                cat['category']
            )
            card.categoryClicked.connect(self.categoryClicked.emit)
            categoriesLayout.addWidget(card, i // 3, i % 3)
        
        layout.addLayout(categoriesLayout)
        layout.addStretch()

