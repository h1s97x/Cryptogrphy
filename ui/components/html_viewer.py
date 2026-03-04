"""
HTML 查看器组件 - 用于显示算法介绍页面
"""

from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QDialog
from PyQt5.QtWebEngineWidgets import QWebEngineView
from qfluentwidgets import (
    CardWidget, BodyLabel, PushButton, 
    FluentIcon as FIF, MessageBox
)
from pathlib import Path


class HTMLViewerCard(CardWidget):
    """HTML 查看器卡片 - 在卡片中嵌入HTML"""
    
    def __init__(self, html_path=None, parent=None):
        super().__init__(parent)
        self.html_path = html_path
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📖 算法介绍")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # Web视图
        self.webView = QWebEngineView()
        self.webView.setMinimumHeight(400)
        layout.addWidget(self.webView)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.openBtn = PushButton(FIF.ZOOM, "全屏查看")
        self.refreshBtn = PushButton(FIF.SYNC, "刷新")
        
        btnLayout.addWidget(self.openBtn)
        btnLayout.addWidget(self.refreshBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
        
        # 连接信号
        self.openBtn.clicked.connect(self.openFullScreen)
        self.refreshBtn.clicked.connect(self.refresh)
        
        # 加载HTML
        if self.html_path:
            self.loadHTML(self.html_path)
    
    def loadHTML(self, html_path):
        """加载HTML文件"""
        self.html_path = html_path
        path = Path(html_path)
        
        if not path.exists():
            self.webView.setHtml(
                f"<html><body><h2>未找到算法介绍页面</h2><p>路径: {html_path}</p></body></html>"
            )
            return
        
        # 使用绝对路径加载HTML
        url = QUrl.fromLocalFile(str(path.absolute()))
        self.webView.load(url)
    
    def refresh(self):
        """刷新页面"""
        if self.html_path:
            self.loadHTML(self.html_path)
    
    def openFullScreen(self):
        """全屏查看"""
        if self.html_path:
            dialog = HTMLViewerDialog(self.html_path, self.window())
            dialog.exec()


class HTMLViewerDialog(QDialog):
    """HTML 查看器对话框 - 全屏显示HTML"""
    
    def __init__(self, html_path, parent=None):
        super().__init__(parent)
        self.html_path = html_path
        self.setWindowTitle("算法介绍")
        self.resize(1200, 800)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Web视图
        self.webView = QWebEngineView()
        layout.addWidget(self.webView)
        
        # 加载HTML
        path = Path(self.html_path)
        if path.exists():
            url = QUrl.fromLocalFile(str(path.absolute()))
            self.webView.load(url)
        else:
            self.webView.setHtml(
                f"<html><body><h2>未找到算法介绍页面</h2><p>路径: {self.html_path}</p></body></html>"
            )
