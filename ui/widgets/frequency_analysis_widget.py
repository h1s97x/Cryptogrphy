"""
频率分析算法界面 - Fluent Design 版本
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFileDialog
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    InfoBar, MessageBox, PushButton, TextEdit, PrimaryPushButton,
    ComboBox, FluentIcon as FIF
)

from ui.components.algorithm_card import LogCard
from core.algorithms.classical.Frequency_Analysis import Thread as FreqThread


class FrequencyAnalysisCard(CardWidget):
    """频率分析卡片"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # 标题
        card_title = BodyLabel("📊 频率分析")
        card_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(card_title)
        
        # 文件路径
        fileLabel = BodyLabel("密文文件")
        layout.addWidget(fileLabel)
        
        fileLayout = QHBoxLayout()
        self.fileEdit = TextEdit()
        self.fileEdit.setPlaceholderText("选择密文文件...")
        self.fileEdit.setMaximumHeight(40)
        fileLayout.addWidget(self.fileEdit)
        
        self.browseBtn = PushButton(FIF.FOLDER, "浏览")
        fileLayout.addWidget(self.browseBtn)
        
        layout.addLayout(fileLayout)
        
        # 分析模式
        modeLabel = BodyLabel("分析模式")
        layout.addWidget(modeLabel)
        
        self.modeCombo = ComboBox()
        self.modeCombo.addItems(["字母出现频率统计", "固定组合解密"])
        self.modeCombo.setCurrentIndex(0)
        layout.addWidget(self.modeCombo)
        
        # 结果显示
        resultLabel = BodyLabel("分析结果")
        layout.addWidget(resultLabel)
        
        self.resultEdit = TextEdit()
        self.resultEdit.setPlaceholderText("分析结果将显示在这里...")
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setMaximumHeight(300)
        layout.addWidget(self.resultEdit)
        
        # 按钮组
        btnLayout = QHBoxLayout()
        
        self.analyzeBtn = PrimaryPushButton(FIF.SEARCH, "开始分析")
        self.clearBtn = PushButton(FIF.DELETE, "清空")
        
        btnLayout.addWidget(self.analyzeBtn)
        btnLayout.addWidget(self.clearBtn)
        btnLayout.addStretch()
        
        layout.addLayout(btnLayout)
    
    def getFilePath(self):
        """获取文件路径"""
        return self.fileEdit.toPlainText()
    
    def setFilePath(self, path):
        """设置文件路径"""
        self.fileEdit.setPlainText(path)
    
    def getMode(self):
        """获取分析模式"""
        return self.modeCombo.currentIndex()
    
    def getResult(self):
        """获取结果"""
        return self.resultEdit.toPlainText()
    
    def setResult(self, text):
        """设置结果"""
        self.resultEdit.setPlainText(text)
    
    def clear(self):
        """清空"""
        self.resultEdit.clear()


class FrequencyAnalysisWidget(ScrollArea):
    """频率分析算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("frequencyAnalysisWidget")
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
        title = TitleLabel("频率分析")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "频率分析是一种密码分析技术，通过统计密文中字母出现的频率来破解替换密码。"
            "支持两种模式：\n"
            "1. 字母出现频率统计 - 统计密文中各字母组合的出现次数\n"
            "2. 固定组合解密 - 使用英文字母频率规律自动解密"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 频率分析卡片
        self.analysisCard = FrequencyAnalysisCard()
        layout.addWidget(self.analysisCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("频率分析算法已加载", "success")
        self.logCard.log("提示：请选择包含英文密文的文本文件", "info")
    
    def connectSignals(self):
        """连接信号"""
        self.analysisCard.browseBtn.clicked.connect(self.browseFile)
        self.analysisCard.analyzeBtn.clicked.connect(self.analyze)
        self.analysisCard.clearBtn.clicked.connect(self.analysisCard.clear)
    
    def browseFile(self):
        """浏览文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择密文文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        
        if file_path:
            self.analysisCard.setFilePath(file_path)
            self.logCard.log(f"已选择文件: {file_path}", "info")
            
            # 读取文件预览
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    preview = f.read(200)
                    if len(preview) == 200:
                        preview += "..."
                    self.logCard.log(f"文件预览: {preview}", "info")
            except Exception as e:
                self.logCard.log(f"读取文件失败: {str(e)}", "warning")
    
    def analyze(self):
        """开始分析"""
        try:
            file_path = self.analysisCard.getFilePath()
            
            if not file_path:
                raise ValueError("请选择密文文件")
            
            # 检查文件是否存在
            import os
            if not os.path.exists(file_path):
                raise ValueError("文件不存在")
            
            mode = self.analysisCard.getMode()
            mode_name = "字母出现频率统计" if mode == 0 else "固定组合解密"
            
            self.logCard.log(f"开始分析...", "info")
            self.logCard.log(f"文件: {file_path}", "info")
            self.logCard.log(f"模式: {mode_name}", "info")
            
            # 创建分析线程
            thread = FreqThread(self, file_path, None, mode)
            thread.final_result.connect(self.onAnalysisFinished)
            thread.logging_result.connect(self.onLoggingResult)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"分析失败: {str(e)}", "error")
            MessageBox("错误", f"分析失败: {str(e)}", self).exec()
    
    def onAnalysisFinished(self, result):
        """分析完成"""
        self.analysisCard.setResult(result)
        self.logCard.log("分析完成", "success")
        
        mode = self.analysisCard.getMode()
        if mode == 0:
            InfoBar.success(
                title="分析完成",
                content="字母频率统计已完成",
                parent=self
            )
        else:
            InfoBar.success(
                title="解密完成",
                content="已生成解密文件",
                parent=self
            )
    
    def onLoggingResult(self, text):
        """日志输出"""
        self.logCard.log(text, "info")
