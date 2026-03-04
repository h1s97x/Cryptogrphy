"""
Euler 定理算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, LineEdit, PrimaryPushButton,
    TextEdit, FluentIcon as FIF
)

from ui.fluent.components.algorithm_card import LogCard
from core.algorithms.mathematical.Euclidean import Thread as EuclideanThread
from core.algorithms.mathematical.Euler import EulerFunctionThread, EulerTheoremThread


class EulerParameterCard(CardWidget):
    """Euler参数卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📐 参数设置")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # a参数
        layout.addWidget(BodyLabel("a (底数)"))
        self.aEdit = LineEdit()
        self.aEdit.setPlaceholderText("输入整数 a")
        self.aEdit.setText("7")
        layout.addWidget(self.aEdit)
        
        # n参数
        layout.addWidget(BodyLabel("n (指数)"))
        self.nEdit = LineEdit()
        self.nEdit.setPlaceholderText("输入整数 n")
        self.nEdit.setText("29")
        layout.addWidget(self.nEdit)
        
        # m参数
        layout.addWidget(BodyLabel("m (模数)"))
        self.mEdit = LineEdit()
        self.mEdit.setPlaceholderText("输入整数 m")
        self.mEdit.setText("10")
        layout.addWidget(self.mEdit)


class EulerResultCard(CardWidget):
    """Euler结果卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📊 计算结果")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # φ(m)结果
        layout.addWidget(BodyLabel("φ(m) - 欧拉函数"))
        self.phiEdit = TextEdit()
        self.phiEdit.setPlaceholderText("欧拉函数结果")
        self.phiEdit.setReadOnly(True)
        self.phiEdit.setMaximumHeight(60)
        layout.addWidget(self.phiEdit)
        
        # a^n mod m结果
        layout.addWidget(BodyLabel("a^n (mod m) - 模幂运算"))
        self.resultEdit = TextEdit()
        self.resultEdit.setPlaceholderText("模幂运算结果")
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setMaximumHeight(60)
        layout.addWidget(self.resultEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.phiBtn = PrimaryPushButton(FIF.LABEL, "计算 φ(m)")
        self.modBtn = PrimaryPushButton(FIF.CALCULATOR, "计算 a^n mod m")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.phiBtn)
        btnLayout.addWidget(self.modBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def clear(self):
        """清空结果"""
        self.phiEdit.clear()
        self.resultEdit.clear()


class EulerWidget(ScrollArea):
    """Euler 定理算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("eulerWidget")
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
        title = TitleLabel("Euler 定理")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "Euler定理：若 gcd(a, m) = 1，则 a^φ(m) ≡ 1 (mod m)。\n"
            "其中 φ(m) 是欧拉函数，表示小于等于m且与m互质的正整数个数。\n"
            "本工具可以计算欧拉函数值和模幂运算结果。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 参数卡片
        self.paramCard = EulerParameterCard()
        layout.addWidget(self.paramCard)
        
        # 结果卡片
        self.resultCard = EulerResultCard()
        layout.addWidget(self.resultCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("Euler 定理算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.resultCard.phiBtn.clicked.connect(self.calculatePhi)
        self.resultCard.modBtn.clicked.connect(self.calculateMod)
        self.resultCard.clearBtn.clicked.connect(self.clear)
    
    def validateInput(self, value, name):
        """验证输入"""
        try:
            if not value.strip():
                raise ValueError(f"{name}不能为空")
            
            if not value.isdigit():
                raise ValueError(f"{name}必须是正整数")
            
            num = int(value)
            if num == 0:
                raise ValueError(f"{name}不能为0")
            
            return True, num
        except Exception as e:
            return False, str(e)
    
    def calculatePhi(self):
        """计算欧拉函数"""
        try:
            self.logCard.log("开始计算欧拉函数...", "info")
            
            # 验证m
            m_text = self.paramCard.mEdit.text()
            valid, result = self.validateInput(m_text, "m")
            if not valid:
                raise ValueError(result)
            
            m = result
            self.logCard.log(f"m = {m}", "info")
            
            # 创建计算线程
            thread = EulerFunctionThread(self, m)
            thread.final_result.connect(self.onPhiFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算失败: {str(e)}", "error")
            MessageBox("错误", f"计算失败: {str(e)}", self).exec()
    
    def onPhiFinished(self, phi_value):
        """欧拉函数计算完成"""
        self.resultCard.phiEdit.setPlainText(phi_value)
        self.logCard.log(f"φ(m) = {phi_value}", "success")
        self.logCard.log("欧拉函数计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content=f"φ(m) = {phi_value}",
            parent=self
        )
    
    def calculateMod(self):
        """计算模幂运算"""
        try:
            self.logCard.log("开始计算模幂运算...", "info")
            
            # 验证a
            a_text = self.paramCard.aEdit.text()
            valid, result = self.validateInput(a_text, "a")
            if not valid:
                raise ValueError(result)
            a = result
            
            # 验证n
            n_text = self.paramCard.nEdit.text()
            valid, result = self.validateInput(n_text, "n")
            if not valid:
                raise ValueError(result)
            n = result
            
            # 验证m
            m_text = self.paramCard.mEdit.text()
            valid, result = self.validateInput(m_text, "m")
            if not valid:
                raise ValueError(result)
            m = result
            
            self.logCard.log(f"a = {a}", "info")
            self.logCard.log(f"n = {n}", "info")
            self.logCard.log(f"m = {m}", "info")
            
            # 计算φ(m)
            phi_m = EulerFunctionThread.euler_phi(m)
            self.resultCard.phiEdit.setPlainText(str(phi_m))
            self.logCard.log(f"φ(m) = {phi_m}", "info")
            
            # 检查gcd(a, m)
            gcd_value = EuclideanThread.gcd(a, m)
            if gcd_value != 1:
                self.logCard.log(f"警告: gcd(a, m) = {gcd_value} ≠ 1", "warning")
                self.logCard.log("a和m不互质，计算可能需要较长时间", "warning")
                flag = 0
            else:
                self.logCard.log("gcd(a, m) = 1，a和m互质", "info")
                flag = 1
            
            # 创建计算线程
            thread = EulerTheoremThread(self, a, n, m, phi_m, flag)
            thread.print_final_result.connect(self.onModFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算失败: {str(e)}", "error")
            MessageBox("错误", f"计算失败: {str(e)}", self).exec()
    
    def onModFinished(self, result_value):
        """模幂运算计算完成"""
        self.resultCard.resultEdit.setPlainText(result_value)
        self.logCard.log(f"a^n (mod m) = {result_value}", "success")
        self.logCard.log("模幂运算计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content=f"结果 = {result_value}",
            parent=self
        )
    
    def clear(self):
        """清空结果"""
        self.resultCard.clear()
        self.logCard.log("结果已清空", "info")
