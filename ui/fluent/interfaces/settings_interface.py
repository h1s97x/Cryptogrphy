"""
设置界面
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from qfluentwidgets import (
    ScrollArea, CardWidget, BodyLabel, TitleLabel,
    PushButton, FluentIcon as FIF, InfoBar, Theme, setTheme
)


class SettingsInterface(ScrollArea):
    """设置界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("settingsInterface")
        self.initUI()
    
    def initUI(self):
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(24)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        title = TitleLabel("设置")
        layout.addWidget(title)
        
        # 外观设置卡片
        appearanceCard = CardWidget()
        appearanceLayout = QVBoxLayout(appearanceCard)
        
        appearanceTitle = BodyLabel("外观")
        appearanceTitle.setStyleSheet("font-weight: bold; font-size: 14px;")
        appearanceLayout.addWidget(appearanceTitle)
        
        # 主题按钮
        themeLabel = BodyLabel("主题模式")
        appearanceLayout.addWidget(themeLabel)
        
        self.lightBtn = PushButton(FIF.BRIGHTNESS, "浅色主题")
        self.lightBtn.clicked.connect(lambda: self.changeTheme(Theme.LIGHT))
        appearanceLayout.addWidget(self.lightBtn)
        
        self.darkBtn = PushButton(FIF.CONSTRACT, "深色主题")
        self.darkBtn.clicked.connect(lambda: self.changeTheme(Theme.DARK))
        appearanceLayout.addWidget(self.darkBtn)
        
        self.autoBtn = PushButton(FIF.SYNC, "跟随系统")
        self.autoBtn.clicked.connect(lambda: self.changeTheme(Theme.AUTO))
        appearanceLayout.addWidget(self.autoBtn)
        
        layout.addWidget(appearanceCard)
        
        # 关于卡片
        aboutCard = CardWidget()
        aboutLayout = QVBoxLayout(aboutCard)
        
        aboutTitle = BodyLabel("关于")
        aboutTitle.setStyleSheet("font-weight: bold; font-size: 14px;")
        aboutLayout.addWidget(aboutTitle)
        
        appName = BodyLabel("密码学平台")
        aboutLayout.addWidget(appName)
        
        version = BodyLabel("版本 2.0.0 (Fluent Design)")
        aboutLayout.addWidget(version)
        
        layout.addWidget(aboutCard)
        
        layout.addStretch()
    
    def changeTheme(self, theme):
        """切换主题"""
        setTheme(theme)
        
        theme_names = {
            Theme.LIGHT: "浅色",
            Theme.DARK: "深色",
            Theme.AUTO: "跟随系统"
        }
        
        # 提示用户重启应用
        InfoBar.warning(
            title="主题已切换",
            content=f"已切换到{theme_names.get(theme, '未知')}主题，请重启应用以完全生效",
            parent=self,
            duration=5000
        )
