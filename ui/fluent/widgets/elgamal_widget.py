"""
ElGamal 公钥密码界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, PlainTextEdit,
    PushButton, InfoBar, MessageBox, CardWidget
)

from ui.fluent.components.algorithm_card import LogCard
from core.algorithms.asymmetric.ElGamal import Thread as ElGamalThread
from infrastructure.converters import TypeConvert


class ElGamalKeyCard(CardWidget):
    """ElGamal密钥卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("密钥参数")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 素数p
        pLabel = BodyLabel("素数 p:")
        layout.addWidget(pLabel)
        
        self.pEdit = PlainTextEdit()
        self.pEdit.setReadOnly(True)
        self.pEdit.setPlaceholderText("点击生成参数...")
        self.pEdit.setMaximumHeight(80)
        layout.addWidget(self.pEdit)
        
        # 生成元a
        aLabel = BodyLabel("生成元 a:")
        layout.addWidget(aLabel)
        
        self.aEdit = PlainTextEdit()
        self.aEdit.setReadOnly(True)
        self.aEdit.setPlaceholderText("点击生成参数...")
        self.aEdit.setMaximumHeight(80)
        layout.addWidget(self.aEdit)
        
        # 私钥x
        xLabel = BodyLabel("私钥 x:")
        layout.addWidget(xLabel)
        
        self.xEdit = PlainTextEdit()
        self.xEdit.setReadOnly(True)
        self.xEdit.setPlaceholderText("点击生成参数...")
        self.xEdit.setMaximumHeight(80)
        layout.addWidget(self.xEdit)
        
        # 公钥y
        yLabel = BodyLabel("公钥 y:")
        layout.addWidget(yLabel)
        
        self.yEdit = PlainTextEdit()
        self.yEdit.setReadOnly(True)
        self.yEdit.setPlaceholderText("点击生成参数...")
        self.yEdit.setMaximumHeight(80)
        layout.addWidget(self.yEdit)
        
        # 生成按钮
        self.generateBtn = PushButton("生成参数")
        layout.addWidget(self.generateBtn)
    
    def setParams(self, p, a, x, y):
        """设置参数"""
        self.pEdit.setPlainText(p)
        self.aEdit.setPlainText(a)
        self.xEdit.setPlainText(x)
        self.yEdit.setPlainText(y)
    
    def getParams(self):
        """获取参数"""
        return (
            self.pEdit.toPlainText(),
            self.aEdit.toPlainText(),
            self.xEdit.toPlainText(),
            self.yEdit.toPlainText()
        )


class ElGamalCryptoCard(CardWidget):
    """ElGamal加密解密卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("加密/解密")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 明文M
        mLabel = BodyLabel("明文 M:")
        layout.addWidget(mLabel)
        
        self.mEdit = PlainTextEdit()
        self.mEdit.setPlaceholderText("输入明文（十六进制）...")
        self.mEdit.setMaximumHeight(80)
        layout.addWidget(self.mEdit)
        
        # 密文C1
        c1Label = BodyLabel("密文 C1:")
        layout.addWidget(c1Label)
        
        self.c1Edit = PlainTextEdit()
        self.c1Edit.setReadOnly(True)
        self.c1Edit.setPlaceholderText("密文C1将显示在这里...")
        self.c1Edit.setMaximumHeight(80)
        layout.addWidget(self.c1Edit)
        
        # 密文C2
        c2Label = BodyLabel("密文 C2:")
        layout.addWidget(c2Label)
        
        self.c2Edit = PlainTextEdit()
        self.c2Edit.setReadOnly(True)
        self.c2Edit.setPlaceholderText("密文C2将显示在这里...")
        self.c2Edit.setMaximumHeight(80)
        layout.addWidget(self.c2Edit)
        
        # 按钮
        btnLayout = QVBoxLayout()
        btnLayout.setSpacing(8)
        
        self.encryptBtn = PushButton("加密")
        btnLayout.addWidget(self.encryptBtn)
        
        self.decryptBtn = PushButton("解密")
        btnLayout.addWidget(self.decryptBtn)
        
        layout.addLayout(btnLayout)


class ElGamalWidget(ScrollArea):
    """ElGamal 公钥密码界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("elgamalWidget")
        self.initUI()
        self.connectSignals()
    
    def initUI(self):
        """初始化UI"""
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(16)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        title = TitleLabel("ElGamal 公钥密码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "ElGamal 是一种基于离散对数问题的公钥密码系统。"
            "使用大素数p、生成元a、私钥x和公钥y=a^x mod p。"
            "加密产生两个密文分量(C1, C2)。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥卡片
        self.keyCard = ElGamalKeyCard()
        layout.addWidget(self.keyCard)
        
        # 加密解密卡片
        self.cryptoCard = ElGamalCryptoCard()
        layout.addWidget(self.cryptoCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("ElGamal 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.keyCard.generateBtn.clicked.connect(self.generateParams)
        self.cryptoCard.encryptBtn.clicked.connect(self.encrypt)
        self.cryptoCard.decryptBtn.clicked.connect(self.decrypt)
    
    def generateParams(self):
        """生成参数"""
        try:
            self.logCard.log("正在生成参数（可能需要几秒钟）...", "info")
            
            # 创建生成线程
            thread = ElGamalThread(self, mode=0)
            thread.final_result.connect(self.onParamsGenerated)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"参数生成失败: {str(e)}", "error")
            MessageBox("错误", f"参数生成失败: {str(e)}", self).exec()
    
    def onParamsGenerated(self, p, a, x, y, m):
        """参数生成完成"""
        self.keyCard.setParams(p, a, x, y)
        self.cryptoCard.mEdit.setPlainText(m)
        
        self.logCard.log("参数生成成功", "success")
        self.logCard.log(f"素数 p: {p[:50]}...", "info")
        self.logCard.log(f"生成元 a: {a[:50]}...", "info")
        self.logCard.log(f"随机明文 M: {m[:50]}...", "info")
        
        InfoBar.success(
            title="生成成功",
            content="ElGamal 参数已生成",
            parent=self
        )
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 获取参数
            p_str, a_str, x_str, y_str = self.keyCard.getParams()
            m_str = self.cryptoCard.mEdit.toPlainText().strip()
            
            if not all([p_str, a_str, y_str, m_str]):
                raise ValueError("请先生成参数并输入明文")
            
            # 转换为整数
            p = TypeConvert.str_to_int(p_str)
            a = TypeConvert.str_to_int(a_str)
            y = TypeConvert.str_to_int(y_str)
            m = TypeConvert.str_to_int(m_str)
            
            if any(v is None for v in [p, a, y, m]):
                raise ValueError("参数格式错误")
            
            self.logCard.log("正在加密...", "info")
            
            # 创建加密线程
            thread = ElGamalThread(self, mode=2, p=p, a=a, y=y, m=m)
            thread.C1_C2.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, c1, c2):
        """加密完成"""
        self.cryptoCard.c1Edit.setPlainText(c1)
        self.cryptoCard.c2Edit.setPlainText(c2)
        
        self.logCard.log(f"C1: {c1[:50]}...", "success")
        self.logCard.log(f"C2: {c2[:50]}...", "success")
        self.logCard.log("加密完成", "success")
        
        InfoBar.success(
            title="加密成功",
            content="明文已成功加密",
            parent=self
        )
    
    def decrypt(self):
        """解密"""
        try:
            self.logCard.log("开始解密...", "info")
            
            # 获取参数
            p_str, a_str, x_str, y_str = self.keyCard.getParams()
            c1_str = self.cryptoCard.c1Edit.toPlainText().strip()
            c2_str = self.cryptoCard.c2Edit.toPlainText().strip()
            
            if not all([p_str, x_str, c1_str, c2_str]):
                raise ValueError("请先加密或输入密文")
            
            # 转换为整数
            p = TypeConvert.str_to_int(p_str)
            x = TypeConvert.str_to_int(x_str)
            c1 = TypeConvert.str_to_int(c1_str)
            c2 = TypeConvert.str_to_int(c2_str)
            
            if any(v is None for v in [p, x, c1, c2]):
                raise ValueError("参数格式错误")
            
            self.logCard.log("正在解密...", "info")
            
            # 创建解密线程
            thread = ElGamalThread(self, mode=1, C1=c1, C2=c2, x=x, p=p)
            thread.M_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, m):
        """解密完成"""
        self.cryptoCard.mEdit.setPlainText(m)
        
        self.logCard.log(f"明文 M: {m[:50]}...", "success")
        self.logCard.log("解密完成", "success")
        
        InfoBar.success(
            title="解密成功",
            content="密文已成功解密",
            parent=self
        )
