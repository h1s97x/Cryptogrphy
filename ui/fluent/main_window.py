"""
Fluent Design 主窗口
使用 QFluentWidgets 实现现代化界面
"""

from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication

from qfluentwidgets import (
    FluentWindow, NavigationItemPosition, FluentIcon,
    setTheme, Theme, setThemeColor, MessageBox
)
from qfluentwidgets import FluentIcon as FIF


class FluentMainWindow(FluentWindow):
    """基于 Fluent Design 的主窗口"""
    
    def __init__(self):
        super().__init__()
        self.initWindow()
        self.initNavigation()
    
    def initWindow(self):
        """初始化窗口"""
        self.setWindowTitle("密码学平台")
        self.resize(1200, 800)
        
        # 设置窗口图标
        # self.setWindowIcon(QIcon('resources/icons/logo.png'))
    
    def initNavigation(self):
        """初始化导航栏"""
        
        # 延迟导入，避免循环依赖
        from ui.fluent.interfaces.home_interface import HomeInterface
        from ui.fluent.interfaces.settings_interface import SettingsInterface
        
        # 首页
        self.homeInterface = HomeInterface(self)
        self.addSubInterface(
            self.homeInterface,
            FIF.HOME,
            '首页',
            NavigationItemPosition.TOP
        )
        
        # 经典密码
        self.addClassicalCrypto()
        
        # 分组密码
        self.addBlockCrypto()
        
        # 公钥密码
        self.addPublicKeyCrypto()
        
        # 哈希算法
        self.addHashAlgorithms()
        
        # 流密码
        self.addStreamCrypto()
        
        # 数学基础
        self.addMathematical()
        
        # 密码协议
        self.addProtocols()
        
        # 设置（底部）
        self.settingsInterface = SettingsInterface(self)
        self.addSubInterface(
            self.settingsInterface,
            FIF.SETTING,
            '设置',
            NavigationItemPosition.BOTTOM
        )
    
    def addClassicalCrypto(self):
        """添加经典密码分类"""
        from ui.fluent.widgets.hill_widget import HillWidget
        from ui.fluent.widgets.caesar_widget import CaesarWidget
        from ui.fluent.widgets.vigenere_widget import VigenereWidget
        from ui.fluent.widgets.playfair_widget import PlayfairWidget
        
        # Hill
        self.hillWidget = HillWidget(self)
        self.hillWidget.setObjectName('hillWidget')
        self.addSubInterface(
            self.hillWidget,
            FIF.DOCUMENT,
            'Hill',
            NavigationItemPosition.SCROLL
        )
        
        # Caesar
        self.caesarWidget = CaesarWidget(self)
        self.caesarWidget.setObjectName('caesarWidget')
        self.addSubInterface(
            self.caesarWidget,
            FIF.DOCUMENT,
            'Caesar',
            NavigationItemPosition.SCROLL
        )
        
        # Vigenere
        self.vigenereWidget = VigenereWidget(self)
        self.vigenereWidget.setObjectName('vigenereWidget')
        self.addSubInterface(
            self.vigenereWidget,
            FIF.DOCUMENT,
            'Vigenere',
            NavigationItemPosition.SCROLL
        )
        
        # Playfair
        self.playfairWidget = PlayfairWidget(self)
        self.playfairWidget.setObjectName('playfairWidget')
        self.addSubInterface(
            self.playfairWidget,
            FIF.DOCUMENT,
            'Playfair',
            NavigationItemPosition.SCROLL
        )
    
    def addBlockCrypto(self):
        """添加分组密码分类"""
        from ui.fluent.widgets.aes_widget import AESWidget
        from ui.fluent.widgets.des_widget import DESWidget
        
        # AES
        self.aesWidget = AESWidget(self)
        self.aesWidget.setObjectName('aesWidget')
        self.addSubInterface(
            self.aesWidget,
            FIF.DOCUMENT,
            'AES',
            NavigationItemPosition.SCROLL
        )
        
        # DES
        self.desWidget = DESWidget(self)
        self.desWidget.setObjectName('desWidget')
        self.addSubInterface(
            self.desWidget,
            FIF.DOCUMENT,
            'DES',
            NavigationItemPosition.SCROLL
        )
    
    def addPublicKeyCrypto(self):
        """添加公钥密码分类"""
        from ui.fluent.widgets.rsa_widget import RSAWidget
        
        # RSA
        self.rsaWidget = RSAWidget(self)
        self.rsaWidget.setObjectName('rsaWidget')
        self.addSubInterface(
            self.rsaWidget,
            FIF.DOCUMENT,
            'RSA',
            NavigationItemPosition.SCROLL
        )
    
    def addHashAlgorithms(self):
        """添加哈希算法分类"""
        from ui.fluent.widgets.md5_widget import MD5Widget
        from ui.fluent.widgets.sha1_widget import SHA1Widget
        from ui.fluent.widgets.sha256_widget import SHA256Widget
        
        # MD5
        self.md5Widget = MD5Widget(self)
        self.md5Widget.setObjectName('md5Widget')
        self.addSubInterface(
            self.md5Widget,
            FIF.DOCUMENT,
            'MD5',
            NavigationItemPosition.SCROLL
        )
        
        # SHA-1
        self.sha1Widget = SHA1Widget(self)
        self.sha1Widget.setObjectName('sha1Widget')
        self.addSubInterface(
            self.sha1Widget,
            FIF.DOCUMENT,
            'SHA-1',
            NavigationItemPosition.SCROLL
        )
        
        # SHA-256
        self.sha256Widget = SHA256Widget(self)
        self.sha256Widget.setObjectName('sha256Widget')
        self.addSubInterface(
            self.sha256Widget,
            FIF.DOCUMENT,
            'SHA-256',
            NavigationItemPosition.SCROLL
        )
    
    def addStreamCrypto(self):
        """添加流密码分类"""
        pass
    
    def addMathematical(self):
        """添加数学基础分类"""
        from ui.fluent.widgets.euler_widget import EulerWidget
        
        # Euler
        self.eulerWidget = EulerWidget(self)
        self.eulerWidget.setObjectName('eulerWidget')
        self.addSubInterface(
            self.eulerWidget,
            FIF.DOCUMENT,
            'Euler',
            NavigationItemPosition.SCROLL
        )
    
    def addProtocols(self):
        """添加密码协议分类"""
        pass


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    window = FluentMainWindow()
    window.show()
    sys.exit(app.exec_())
