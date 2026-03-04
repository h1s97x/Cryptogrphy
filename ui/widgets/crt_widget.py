"""
中国剩余定理 (CRT) 界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, LineEdit,
    PushButton, InfoBar, MessageBox, CardWidget, PlainTextEdit
)

from ui.components.algorithm_card import LogCard
from core.algorithms.mathematical.CRT import Thread as CRTThread


class CRTInputCard(CardWidget):
    """CRT 输入卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("同余方程组")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 说明
        desc = BodyLabel(
            "输入同余方程组 x ≡ aᵢ (mod mᵢ)，其中 mᵢ 必须两两互质。\n"
            "每行输入一个方程，格式：aᵢ mᵢ（用空格分隔）"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 输入区域
        inputLabel = BodyLabel("方程组:")
        layout.addWidget(inputLabel)
        
        self.equationsEdit = PlainTextEdit()
        self.equationsEdit.setPlaceholderText(
            "示例:\n"
            "2 3\n"
            "3 5\n"
            "2 7\n"
            "表示:\n"
            "x ≡ 2 (mod 3)\n"
            "x ≡ 3 (mod 5)\n"
            "x ≡ 2 (mod 7)"
        )
        self.equationsEdit.setMaximumHeight(150)
        layout.addWidget(self.equationsEdit)
        
        # 示例按钮
        self.exampleBtn = PushButton("加载示例")
        layout.addWidget(self.exampleBtn)
    
    def getEquations(self):
        """获取方程组"""
        text = self.equationsEdit.toPlainText().strip()
        if not text:
            return [], []
        
        a_list = []
        m_list = []
        
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) != 2:
                raise ValueError(f"格式错误: {line}")
            
            try:
                a = int(parts[0])
                m = int(parts[1])
                
                if m <= 0:
                    raise ValueError(f"模数必须为正整数: {m}")
                
                a_list.append(a)
                m_list.append(m)
            except ValueError as e:
                raise ValueError(f"数值错误: {line}")
        
        if len(a_list) < 2:
            raise ValueError("至少需要2个方程")
        
        return a_list, m_list
    
    def setExample(self):
        """设置示例"""
        self.equationsEdit.setPlainText("2 3\n3 5\n2 7")


class CRTResultCard(CardWidget):
    """CRT 结果卡片"""
    
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
        
        # 结果显示
        resultLabel = BodyLabel("解 x =")
        layout.addWidget(resultLabel)
        
        self.resultEdit = LineEdit()
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setPlaceholderText("计算结果将显示在这里...")
        layout.addWidget(self.resultEdit)
        
        # 复制按钮
        self.copyBtn = PushButton("复制结果")
        layout.addWidget(self.copyBtn)
    
    def setResult(self, result):
        """设置结果"""
        self.resultEdit.setText(str(result))
    
    def getResult(self):
        """获取结果"""
        return self.resultEdit.text()
    
    def clear(self):
        """清空"""
        self.resultEdit.clear()


class CRTWidget(ScrollArea):
    """中国剩余定理界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("crtWidget")
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
        title = TitleLabel("中国剩余定理 (CRT)")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "中国剩余定理用于求解一次同余方程组。"
            "给定方程组 x ≡ aᵢ (mod mᵢ)，其中 mᵢ 两两互质，"
            "可以求出唯一解 x (mod M)，其中 M = m₁ × m₂ × ... × mₙ。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 输入卡片
        self.inputCard = CRTInputCard()
        layout.addWidget(self.inputCard)
        
        # 计算按钮
        self.calculateBtn = PushButton("计算")
        self.calculateBtn.setFixedWidth(200)
        layout.addWidget(self.calculateBtn)
        
        # 结果卡片
        self.resultCard = CRTResultCard()
        layout.addWidget(self.resultCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("中国剩余定理已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        self.inputCard.exampleBtn.clicked.connect(self.loadExample)
        self.calculateBtn.clicked.connect(self.calculate)
        self.resultCard.copyBtn.clicked.connect(self.copyResult)
    
    def loadExample(self):
        """加载示例"""
        self.inputCard.setExample()
        self.logCard.log("已加载示例方程组", "info")
        InfoBar.success(title="示例", content="已加载示例方程组", parent=self)
    
    def checkCoprime(self, m_list):
        """检查模数是否两两互质"""
        from math import gcd
        
        for i in range(len(m_list)):
            for j in range(i + 1, len(m_list)):
                if gcd(m_list[i], m_list[j]) != 1:
                    return False, f"m{i+1}={m_list[i]} 和 m{j+1}={m_list[j]} 不互质"
        
        return True, ""
    
    def calculate(self):
        """计算"""
        try:
            self.logCard.log("开始计算...", "info")
            
            # 获取方程组
            a_list, m_list = self.inputCard.getEquations()
            
            # 检查互质性
            is_coprime, error_msg = self.checkCoprime(m_list)
            if not is_coprime:
                raise ValueError(error_msg)
            
            # 显示方程组
            self.logCard.log("方程组:", "info")
            for i in range(len(a_list)):
                self.logCard.log(f"  x ≡ {a_list[i]} (mod {m_list[i]})", "info")
            
            # 创建计算线程
            thread = CRTThread(self, a_list, m_list)
            thread.print_final_result.connect(self.onCalculateFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"计算失败: {str(e)}", "error")
            MessageBox("错误", f"计算失败: {str(e)}", self).exec()
    
    def onCalculateFinished(self, result):
        """计算完成"""
        self.resultCard.setResult(result)
        
        # 计算M
        a_list, m_list = self.inputCard.getEquations()
        M = 1
        for m in m_list:
            M *= m
        
        self.logCard.log(f"解: x ≡ {result} (mod {M})", "success")
        self.logCard.log("计算完成", "success")
        
        InfoBar.success(
            title="计算成功",
            content=f"x = {result}",
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
