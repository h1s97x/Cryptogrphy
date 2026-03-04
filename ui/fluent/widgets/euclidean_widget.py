"""
欧几里得算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, LineEdit,
    PushButton, InfoBar, MessageBox, CardWidget
)

from ui.fluent.components.algorithm_card import LogCard
from core.algorithms.mathematical.Euclidean import Thread as EuclideanThread


class EuclideanInputCard(CardWidget):
    """欧几里得算法输入卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("输入参数")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 说明
        desc = BodyLabel("计算两个整数的最大公约数 (GCD)")
        layout.addWidget(desc)
        
        # 第一个数
        aLabel = BodyLabel("整数 a:")
        layout.addWidget(aLabel)
        
        self.aEdit = LineEdit()
        self.aEdit.setPlaceholderText("输入第一个整数...")
        self.aEdit.setText("48")
        layout.addWidget(self.aEdit)
        
        # 第二个数
        bLabel = BodyLabel("整数 b:")
        layout.addWidget(bLabel)
        
        self.bEdit = LineEdit()
        self.bEdit.setPlaceholderText("输入第二个整数...")
        self.bEdit.setText("18")
        layout.addWidget(self.bEdit)
    
    def getValues(self):
        """获取输入值"""
        try:
            a = int(self.aEdit.text().strip())
            b = int(self.bEdit.text().strip())
            return a, b
        except ValueError:
            raise ValueError("请输入有效的整数")


class EuclideanResultCard(CardWidget):
    """欧几里得算法结果卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("计算结果")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # GCD结果
        gcdLabel = BodyLabel("最大公约数 (GCD):")
        layout.addWidget(gcdLabel)
        
        self.gcdEdit = LineEdit()
        self.gcdEdit.setReadOnly(True)
        self.gcdEdit.setPlaceholderText("计算结果将显示在这里...")
        layout.addWidget(self.gcdEdit)
        
        # 复制按钮
        self.copyBtn = PushButton("复制结果")
        layout.addWidget(self.copyBtn)
    
    def setResult(self, gcd):
        """设置结果"""
        self.gcdEdit.setText(str(gcd))
    
    def getResult(self):
        """获取结果"""
        return self.gcdEdit.text()
    
    def clear(self):
        """清空"""
        self.gcdEdit.clear()


class EuclideanWidget(ScrollArea):
    """欧几里得算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("euclideanWidget")
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
        title = TitleLabel("欧几里得算法")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "欧几里得算法（辗转相除法）用于计算两个整数的最大公约数 (GCD)。"
            "算法基于原理：gcd(a, b) = gcd(b, a mod b)。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 输入卡片
        self.inputCard = EuclideanInputCard()
        layout.addWidget(self.inputCard)
        
        # 计算按钮
        self.calculateBtn = PushButton("计算 GCD")
        self.calculateBtn.setFixedWidth(200)
        layout.addWidget(self.calculateBtn)
        
        # 结果卡片
        self.resultCard = EuclideanResultCard()
        layout.addWidget(self.resultCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("欧几里得算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.calculateBtn.clicked.connect(self.calculate)
        self.resultCard.copyBtn.clicked.connect(self.copyResult)
    
    def calculate(self):
        """计算GCD"""
        try:
            self.logCard.log("开始计算...", "info")
            
            # 获取输入
            a, b = self.inputCard.getValues()
            
            if a <= 0 or b <= 0:
                raise ValueError("输入必须是正整数")
            
            self.logCard.log(f"a = {a}", "info")
            self.logCard.log(f"b = {b}", "info")
            
            # 创建计算线程
            thread = EuclideanThread(self, a, b)
            thread.final_result.connect(self.onCalculateFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算失败: {str(e)}", "error")
            MessageBox("错误", f"计算失败: {str(e)}", self).exec()
    
    def onCalculateFinished(self, result):
        """计算完成"""
        self.resultCard.setResult(result)
        
        a, b = self.inputCard.getValues()
        self.logCard.log(f"gcd({a}, {b}) = {result}", "success")
        self.logCard.log("计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content=f"GCD = {result}",
            parent=self
        )
    
    def copyResult(self):
        """复制结果"""
        from PyQt5.QtWidgets import QApplication
        result = self.resultCard.getResult()
        if not result:
            InfoBar.warning(title="提示", content="没有可复制的结果", parent=self)
            return
        
        QApplication.clipboard().setText(result)
        InfoBar.success(title="已复制", content="结果已复制到剪贴板", parent=self)
        self.logCard.log("结果已复制到剪贴板", "info")
