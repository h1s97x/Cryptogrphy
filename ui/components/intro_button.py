"""
算法介绍按钮组件
"""

from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtWidgets import QVBoxLayout, QDialog
from PyQt5.QtWebEngineWidgets import QWebEngineView
from qfluentwidgets import PushButton, FluentIcon as FIF, InfoBar
from pathlib import Path


class AlgorithmIntroButton(PushButton):
    """算法介绍按钮 - 点击打开HTML介绍页面"""
    
    def __init__(self, algorithm_name, parent=None):
        # 先初始化父类
        super().__init__(parent=parent)
        
        # 设置按钮属性
        self.setText("算法介绍")
        self.setIcon(FIF.BOOK_SHELF)
        
        # 设置算法相关属性
        self.algorithm_name = algorithm_name
        self.html_path = self._getHTMLPath()
        
        # 连接信号
        self.clicked.connect(self.showIntro)
    
    def _getHTMLPath(self):
        """获取HTML文件路径"""
        # 算法名称映射到HTML目录名
        name_map = {
            'AES': 'aes',
            'Caesar': 'caesar',
            'DES': 'des',
            'Hill': 'hill',
            'MD5': 'md5',
            'SM4': 'sm4',
            'Vigenere': 'vigenere'
        }
        
        dir_name = name_map.get(self.algorithm_name)
        if not dir_name:
            return None
        
        # 构建HTML路径
        html_path = Path('resources') / 'html' / dir_name / 'index.html'
        return str(html_path) if html_path.exists() else None
    
    def showIntro(self):
        """显示算法介绍"""
        if not self.html_path:
            InfoBar.warning(
                title="暂无介绍",
                content=f"{self.algorithm_name} 算法介绍页面尚未添加",
                parent=self.window()
            )
            return
        
        # 打开对话框显示HTML
        dialog = AlgorithmIntroDialog(self.algorithm_name, self.html_path, self.window())
        dialog.exec()


class AlgorithmIntroDialog(QDialog):
    """算法介绍对话框"""
    
    def __init__(self, algorithm_name, html_path, parent=None):
        super().__init__(parent)
        self.algorithm_name = algorithm_name
        self.html_path = html_path
        self.setWindowTitle(f"{algorithm_name} 算法介绍")
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
                f"<html><body style='padding: 40px; font-family: sans-serif;'>"
                f"<h2>未找到算法介绍页面</h2>"
                f"<p>路径: {self.html_path}</p>"
                f"</body></html>"
            )
