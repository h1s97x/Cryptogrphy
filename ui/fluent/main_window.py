"""
Fluent Design 主窗口
使用 QFluentWidgets 实现现代化界面，支持分层导航
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
        self.initCategoryInterfaces()
        self.connectSignals()
    
    def initWindow(self):
        """初始化窗口"""
        self.setWindowTitle("密码学平台")
        self.resize(1200, 800)
    
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
        
        # 创建分类导航组
        self.navigationInterface.addSeparator(NavigationItemPosition.SCROLL)
        
        # 经典密码
        self.addNavigationGroup('经典密码', FIF.FONT, 'classical')
        
        # 对称密码
        self.addNavigationGroup('对称密码', FIF.FINGERPRINT, 'symmetric')
        
        # 公钥密码
        self.addNavigationGroup('公钥密码', FIF.CERTIFICATE, 'asymmetric')
        
        # 哈希算法
        self.addNavigationGroup('哈希算法', FIF.TAG, 'hash')
        
        # 数学基础
        self.addNavigationGroup('数学基础', FIF.EDIT, 'mathematical')
        
        # 设置（底部）
        self.settingsInterface = SettingsInterface(self)
        self.addSubInterface(
            self.settingsInterface,
            FIF.SETTING,
            '设置',
            NavigationItemPosition.BOTTOM
        )
    
    def addNavigationGroup(self, title, icon, category):
        """添加导航组"""
        # 创建父节点
        self.navigationInterface.addItem(
            routeKey=f'{category}_group',
            icon=icon,
            text=title,
            onClick=lambda: self.switchTo(self.categoryInterfaces[category]),
            position=NavigationItemPosition.SCROLL
        )
    
    def initCategoryInterfaces(self):
        """初始化分类界面"""
        from ui.fluent.interfaces.category_interface import CategoryInterface
        
        self.categoryInterfaces = {}
        self.algorithmWidgets = {}
        
        # 经典密码分类
        self.categoryInterfaces['classical'] = CategoryInterface(
            '经典密码',
            '古典密码学算法，包括替换密码、置换密码等',
            [
                {'icon': FIF.DOCUMENT, 'name': 'Hill', 'description': '基于矩阵运算的多表替换密码', 'objectName': 'hillWidget'},
                {'icon': FIF.DOCUMENT, 'name': 'Caesar', 'description': '最简单的移位替换密码', 'objectName': 'caesarWidget'},
                {'icon': FIF.DOCUMENT, 'name': 'Vigenere', 'description': '多表替换密码，使用密钥字', 'objectName': 'vigenereWidget'},
                {'icon': FIF.DOCUMENT, 'name': 'Playfair', 'description': '双字母替换密码', 'objectName': 'playfairWidget'},
                {'icon': FIF.DOCUMENT, 'name': 'Enigma', 'description': '二战德军使用的转子密码机', 'objectName': 'enigmaWidget'},
                {'icon': FIF.DOCUMENT, 'name': 'Monoalphabetic', 'description': '单表替换密码', 'objectName': 'monoWidget'},
                {'icon': FIF.DOCUMENT, 'name': 'Frequency Analysis', 'description': '频率分析破解工具', 'objectName': 'freqWidget'},
            ],
            self
        )
        
        # 对称密码分类
        self.categoryInterfaces['symmetric'] = CategoryInterface(
            '对称密码',
            '现代分组密码和流密码算法',
            [
                {'icon': FIF.FINGERPRINT, 'name': 'AES', 'description': '高级加密标准，最广泛使用', 'objectName': 'aesWidget'},
                {'icon': FIF.FINGERPRINT, 'name': 'DES', 'description': '数据加密标准', 'objectName': 'desWidget'},
                {'icon': FIF.FINGERPRINT, 'name': 'SM4', 'description': '国密分组密码算法', 'objectName': 'sm4Widget'},
                {'icon': FIF.FINGERPRINT, 'name': 'RC4', 'description': '流密码算法', 'objectName': 'rc4Widget'},
                {'icon': FIF.FINGERPRINT, 'name': 'SPECK', 'description': 'NSA轻量级分组密码', 'objectName': 'speckWidget'},
                {'icon': FIF.FINGERPRINT, 'name': 'SIMON', 'description': 'NSA轻量级分组密码', 'objectName': 'simonWidget'},
                {'icon': FIF.FINGERPRINT, 'name': 'Block Mode', 'description': 'ECB和CBC分组模式', 'objectName': 'blockModeWidget'},
            ],
            self
        )
        
        # 公钥密码分类
        self.categoryInterfaces['asymmetric'] = CategoryInterface(
            '公钥密码',
            '非对称加密和数字签名算法',
            [
                {'icon': FIF.CERTIFICATE, 'name': 'RSA', 'description': '最常用的公钥加密算法', 'objectName': 'rsaWidget'},
                {'icon': FIF.CERTIFICATE, 'name': 'RSA Sign', 'description': 'RSA数字签名', 'objectName': 'rsaSignWidget'},
                {'icon': FIF.CERTIFICATE, 'name': 'ElGamal', 'description': '基于离散对数的公钥密码', 'objectName': 'elgamalWidget'},
                {'icon': FIF.CERTIFICATE, 'name': 'ECDSA', 'description': '椭圆曲线数字签名算法', 'objectName': 'ecdsaWidget'},
            ],
            self
        )
        
        # 哈希算法分类
        self.categoryInterfaces['hash'] = CategoryInterface(
            '哈希算法',
            '消息摘要和消息认证码算法',
            [
                {'icon': FIF.TAG, 'name': 'MD5', 'description': '128位消息摘要算法', 'objectName': 'md5Widget'},
                {'icon': FIF.TAG, 'name': 'SHA-1', 'description': '160位安全哈希算法', 'objectName': 'sha1Widget'},
                {'icon': FIF.TAG, 'name': 'SHA-256', 'description': 'SHA-2系列256位哈希', 'objectName': 'sha256Widget'},
                {'icon': FIF.TAG, 'name': 'SHA-3', 'description': '最新的哈希标准', 'objectName': 'sha3Widget'},
                {'icon': FIF.TAG, 'name': 'SM3', 'description': '国密哈希算法', 'objectName': 'sm3Widget'},
                {'icon': FIF.TAG, 'name': 'HMAC-MD5', 'description': '基于MD5的消息认证码', 'objectName': 'hmacmd5Widget'},
                {'icon': FIF.TAG, 'name': 'AES-CBC-MAC', 'description': '基于AES-CBC的MAC', 'objectName': 'aesCbcMacWidget'},
            ],
            self
        )
        
        # 数学基础分类
        self.categoryInterfaces['mathematical'] = CategoryInterface(
            '数学基础',
            '密码学相关的数学算法和定理',
            [
                {'icon': FIF.EDIT, 'name': 'Euler', 'description': '欧拉定理和欧拉函数', 'objectName': 'eulerWidget'},
                {'icon': FIF.EDIT, 'name': 'CRT', 'description': '中国剩余定理', 'objectName': 'crtWidget'},
                {'icon': FIF.EDIT, 'name': 'Euclidean', 'description': '欧几里得算法求最大公约数', 'objectName': 'euclideanWidget'},
            ],
            self
        )
        
        # 将分类界面添加到窗口（但不添加到导航栏）
        for category, interface in self.categoryInterfaces.items():
            self.stackedWidget.addWidget(interface)
    
    def connectSignals(self):
        """连接信号"""
        # 首页分类点击
        self.homeInterface.categoryClicked.connect(self.onCategoryClicked)
        
        # 分类界面算法点击
        for interface in self.categoryInterfaces.values():
            interface.algorithmClicked.connect(self.onAlgorithmClicked)
    
    def onCategoryClicked(self, category):
        """分类卡片点击"""
        if category in self.categoryInterfaces:
            self.switchTo(self.categoryInterfaces[category])
    
    def onAlgorithmClicked(self, objectName):
        """算法卡片点击"""
        # 延迟加载算法Widget
        if objectName not in self.algorithmWidgets:
            self.loadAlgorithmWidget(objectName)
        
        # 切换到算法界面
        if objectName in self.algorithmWidgets:
            self.switchTo(self.algorithmWidgets[objectName])
    
    def loadAlgorithmWidget(self, objectName):
        """延迟加载算法Widget"""
        widget_map = {
            # 经典密码
            'hillWidget': ('ui.fluent.widgets.hill_widget', 'HillWidget'),
            'caesarWidget': ('ui.fluent.widgets.caesar_widget', 'CaesarWidget'),
            'vigenereWidget': ('ui.fluent.widgets.vigenere_widget', 'VigenereWidget'),
            'playfairWidget': ('ui.fluent.widgets.playfair_widget', 'PlayfairWidget'),
            'enigmaWidget': ('ui.fluent.widgets.enigma_widget', 'EnigmaWidget'),
            'monoWidget': ('ui.fluent.widgets.monoalphabetic_widget', 'MonoalphabeticWidget'),
            'freqWidget': ('ui.fluent.widgets.frequency_analysis_widget', 'FrequencyAnalysisWidget'),
            
            # 对称密码
            'aesWidget': ('ui.fluent.widgets.aes_widget', 'AESWidget'),
            'desWidget': ('ui.fluent.widgets.des_widget', 'DESWidget'),
            'sm4Widget': ('ui.fluent.widgets.sm4_widget', 'SM4Widget'),
            'rc4Widget': ('ui.fluent.widgets.rc4_widget', 'RC4Widget'),
            'speckWidget': ('ui.fluent.widgets.speck_widget', 'SPECKWidget'),
            'simonWidget': ('ui.fluent.widgets.simon_widget', 'SIMONWidget'),
            'blockModeWidget': ('ui.fluent.widgets.block_mode_widget', 'BlockModeWidget'),
            
            # 公钥密码
            'rsaWidget': ('ui.fluent.widgets.rsa_widget', 'RSAWidget'),
            'rsaSignWidget': ('ui.fluent.widgets.rsa_sign_widget', 'RSASignWidget'),
            'elgamalWidget': ('ui.fluent.widgets.elgamal_widget', 'ElGamalWidget'),
            'ecdsaWidget': ('ui.fluent.widgets.ecdsa_widget', 'ECDSAWidget'),
            
            # 哈希算法
            'md5Widget': ('ui.fluent.widgets.md5_widget', 'MD5Widget'),
            'sha1Widget': ('ui.fluent.widgets.sha1_widget', 'SHA1Widget'),
            'sha256Widget': ('ui.fluent.widgets.sha256_widget', 'SHA256Widget'),
            'sha3Widget': ('ui.fluent.widgets.sha3_widget', 'SHA3Widget'),
            'sm3Widget': ('ui.fluent.widgets.sm3_widget', 'SM3Widget'),
            'hmacmd5Widget': ('ui.fluent.widgets.hmac_md5_widget', 'HMACMD5Widget'),
            'aesCbcMacWidget': ('ui.fluent.widgets.aes_cbc_mac_widget', 'AESCBCMACWidget'),
            
            # 数学基础
            'eulerWidget': ('ui.fluent.widgets.euler_widget', 'EulerWidget'),
            'crtWidget': ('ui.fluent.widgets.crt_widget', 'CRTWidget'),
            'euclideanWidget': ('ui.fluent.widgets.euclidean_widget', 'EuclideanWidget'),
        }
        
        if objectName in widget_map:
            module_path, class_name = widget_map[objectName]
            try:
                # 动态导入
                module = __import__(module_path, fromlist=[class_name])
                widget_class = getattr(module, class_name)
                widget = widget_class(self)
                widget.setObjectName(objectName)
                
                # 添加到stackedWidget
                self.stackedWidget.addWidget(widget)
                self.algorithmWidgets[objectName] = widget
                
            except Exception as e:
                MessageBox("错误", f"加载算法失败: {str(e)}", self).exec()


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    window = FluentMainWindow()
    window.show()
    sys.exit(app.exec_())
