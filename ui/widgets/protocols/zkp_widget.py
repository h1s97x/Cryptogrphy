"""
零知识证明 - Fluent Design 版本

演示场景：阿里巴巴洞穴问题
Peggy（证明者）想向Victor（验证者）证明她知道洞穴的密码，但不想透露密码本身。

协议步骤：
1. Peggy 随机选择从 A 或 B 入口进入洞穴
2. Victor 随机要求 Peggy 从 A 或 B 出口出来
3. 如果 Peggy 知道密码，她总能从指定出口出来
4. 如果 Peggy 不知道密码，她只有 50% 的概率从正确的出口出来
5. 重复多次验证，如果 Peggy 每次都成功，则可以确信她知道密码

注：本版本模拟零知识证明的基本原理
"""

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    InfoBar, MessageBox, FluentIcon as FIF, ComboBox
)

import random


class ZKPWidget(ScrollArea):
    """零知识证明演示界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("zkpWidget")
        self.knows_password = True  # Peggy 是否知道密码
        self.verification_count = 0
        self.success_count = 0
        self.initUI()
    
    def initUI(self):
        """初始化UI"""
        self.view = QWidget()
        self.setWidget(self.view)
        self.setWidgetResizable(True)
        
        layout = QVBoxLayout(self.view)
        layout.setSpacing(16)
        layout.setContentsMargins(36, 36, 36, 36)
        
        # 标题
        title = TitleLabel("零知识证明 - 阿里巴巴洞穴")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "演示场景：Peggy 想向 Victor 证明她知道洞穴的密码，但不想透露密码本身。\n"
            "通过多次随机验证，Victor 可以确信 Peggy 知道密码，而无需知道密码是什么。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 1. 设置卡片
        self.setupCard = self.createSetupCard()
        layout.addWidget(self.setupCard)
        
        # 2. 单次验证卡片
        self.singleCard = self.createSingleVerificationCard()
        layout.addWidget(self.singleCard)
        
        # 3. 批量验证卡片
        self.batchCard = self.createBatchVerificationCard()
        layout.addWidget(self.batchCard)
        
        # 4. 统计卡片
        self.statsCard = self.createStatsCard()
        layout.addWidget(self.statsCard)
        
        # 5. 日志卡片
        self.logCard = self.createLogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        self.log("零知识证明演示已加载", "success")
        self.log("场景：Peggy 想证明她知道洞穴密码，但不透露密码", "info")
    
    def createSetupCard(self):
        """创建设置卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("⚙️ 设置")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # Peggy 是否知道密码
        knowsLabel = BodyLabel("Peggy 是否知道密码？")
        layout.addWidget(knowsLabel)
        
        self.knowsComboBox = ComboBox()
        self.knowsComboBox.addItems(["知道密码", "不知道密码"])
        self.knowsComboBox.setCurrentIndex(0)
        self.knowsComboBox.currentIndexChanged.connect(self.onKnowsChanged)
        layout.addWidget(self.knowsComboBox)
        
        # 说明
        self.explainLabel = BodyLabel(
            "✅ Peggy 知道密码：每次验证都能成功（100%成功率）\n"
            "❌ Peggy 不知道密码：每次验证只有50%概率成功"
        )
        self.explainLabel.setWordWrap(True)
        self.explainLabel.setStyleSheet("color: #10b981; padding: 8px; background: #f0fdf4; border-radius: 4px;")
        layout.addWidget(self.explainLabel)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.resetBtn = PushButton(FIF.SYNC, "重置统计")
        self.resetBtn.clicked.connect(self.resetStats)
        btnLayout.addWidget(self.resetBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createSingleVerificationCard(self):
        """创建单次验证卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔍 单次验证")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # Peggy 选择的入口
        peggyLabel = BodyLabel("Peggy 选择的入口")
        layout.addWidget(peggyLabel)
        self.peggyEntranceEdit = LineEdit()
        self.peggyEntranceEdit.setReadOnly(True)
        self.peggyEntranceEdit.setPlaceholderText("点击'Peggy进入'...")
        layout.addWidget(self.peggyEntranceEdit)
        
        # Victor 要求的出口
        victorLabel = BodyLabel("Victor 要求的出口")
        layout.addWidget(victorLabel)
        self.victorExitEdit = LineEdit()
        self.victorExitEdit.setReadOnly(True)
        self.victorExitEdit.setPlaceholderText("点击'Victor要求'...")
        layout.addWidget(self.victorExitEdit)
        
        # 验证结果
        resultLabel = BodyLabel("验证结果")
        layout.addWidget(resultLabel)
        self.singleResultEdit = TextEdit()
        self.singleResultEdit.setReadOnly(True)
        self.singleResultEdit.setMaximumHeight(60)
        self.singleResultEdit.setPlaceholderText("验证结果...")
        layout.addWidget(self.singleResultEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.peggyEnterBtn = PrimaryPushButton(FIF.PEOPLE, "1. Peggy 进入")
        self.peggyEnterBtn.clicked.connect(self.peggyEnter)
        self.victorAskBtn = PushButton(FIF.QUESTION, "2. Victor 要求")
        self.victorAskBtn.clicked.connect(self.victorAsk)
        self.verifyBtn = PushButton(FIF.ACCEPT, "3. 验证")
        self.verifyBtn.clicked.connect(self.verifySingle)
        self.clearSingleBtn = PushButton(FIF.DELETE, "清空")
        self.clearSingleBtn.clicked.connect(self.clearSingle)
        
        btnLayout.addWidget(self.peggyEnterBtn)
        btnLayout.addWidget(self.victorAskBtn)
        btnLayout.addWidget(self.verifyBtn)
        btnLayout.addWidget(self.clearSingleBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createBatchVerificationCard(self):
        """创建批量验证卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🔄 批量验证")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 验证次数
        countLabel = BodyLabel("验证次数（1-1000）")
        layout.addWidget(countLabel)
        self.batchCountEdit = LineEdit()
        self.batchCountEdit.setText("10")
        self.batchCountEdit.setPlaceholderText("输入验证次数...")
        layout.addWidget(self.batchCountEdit)
        
        # 批量结果
        batchResultLabel = BodyLabel("批量验证结果")
        layout.addWidget(batchResultLabel)
        self.batchResultEdit = TextEdit()
        self.batchResultEdit.setReadOnly(True)
        self.batchResultEdit.setMaximumHeight(100)
        self.batchResultEdit.setPlaceholderText("批量验证结果...")
        layout.addWidget(self.batchResultEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.batchVerifyBtn = PrimaryPushButton(FIF.PLAY, "批量验证")
        self.batchVerifyBtn.clicked.connect(self.verifyBatch)
        self.clearBatchBtn = PushButton(FIF.DELETE, "清空")
        self.clearBatchBtn.clicked.connect(self.clearBatch)
        
        btnLayout.addWidget(self.batchVerifyBtn)
        btnLayout.addWidget(self.clearBatchBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createStatsCard(self):
        """创建统计卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📊 统计信息")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 统计信息
        statsLayout = QHBoxLayout()
        
        # 总验证次数
        totalLayout = QVBoxLayout()
        totalLabel = BodyLabel("总验证次数")
        totalLayout.addWidget(totalLabel)
        self.totalCountEdit = LineEdit()
        self.totalCountEdit.setReadOnly(True)
        self.totalCountEdit.setText("0")
        totalLayout.addWidget(self.totalCountEdit)
        statsLayout.addLayout(totalLayout)
        
        # 成功次数
        successLayout = QVBoxLayout()
        successLabel = BodyLabel("成功次数")
        successLayout.addWidget(successLabel)
        self.successCountEdit = LineEdit()
        self.successCountEdit.setReadOnly(True)
        self.successCountEdit.setText("0")
        successLayout.addWidget(self.successCountEdit)
        statsLayout.addLayout(successLayout)
        
        # 成功率
        rateLayout = QVBoxLayout()
        rateLabel = BodyLabel("成功率")
        rateLayout.addWidget(rateLabel)
        self.successRateEdit = LineEdit()
        self.successRateEdit.setReadOnly(True)
        self.successRateEdit.setText("0%")
        rateLayout.addWidget(self.successRateEdit)
        statsLayout.addLayout(rateLayout)
        
        layout.addLayout(statsLayout)
        
        # 结论
        conclusionLabel = BodyLabel("结论")
        layout.addWidget(conclusionLabel)
        self.conclusionEdit = TextEdit()
        self.conclusionEdit.setReadOnly(True)
        self.conclusionEdit.setMaximumHeight(80)
        self.conclusionEdit.setPlaceholderText("进行验证后显示结论...")
        layout.addWidget(self.conclusionEdit)
        
        return card
    
    def createLogCard(self):
        """创建日志卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(8)
        
        title = BodyLabel("📊 操作日志")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        self.logEdit = TextEdit()
        self.logEdit.setReadOnly(True)
        self.logEdit.setMaximumHeight(150)
        layout.addWidget(self.logEdit)
        
        btnLayout = QHBoxLayout()
        self.clearLogBtn = PushButton(FIF.DELETE, "清空日志")
        self.clearLogBtn.clicked.connect(lambda: self.logEdit.clear())
        btnLayout.addWidget(self.clearLogBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    # ========== 功能实现 ==========
    
    def onKnowsChanged(self, index):
        """Peggy 知道密码状态改变"""
        self.knows_password = (index == 0)
        
        if self.knows_password:
            self.explainLabel.setText(
                "✅ Peggy 知道密码：每次验证都能成功（100%成功率）\n"
                "❌ Peggy 不知道密码：每次验证只有50%概率成功"
            )
            self.explainLabel.setStyleSheet("color: #10b981; padding: 8px; background: #f0fdf4; border-radius: 4px;")
            self.log("设置：Peggy 知道密码", "success")
        else:
            self.explainLabel.setText(
                "✅ Peggy 知道密码：每次验证都能成功（100%成功率）\n"
                "❌ Peggy 不知道密码：每次验证只有50%概率成功"
            )
            self.explainLabel.setStyleSheet("color: #ef4444; padding: 8px; background: #fef2f2; border-radius: 4px;")
            self.log("设置：Peggy 不知道密码", "warning")
    
    def resetStats(self):
        """重置统计"""
        self.verification_count = 0
        self.success_count = 0
        self.updateStats()
        self.log("统计已重置", "info")
        InfoBar.success(
            title="重置成功",
            content="统计信息已重置",
            parent=self
        )
    
    def peggyEnter(self):
        """Peggy 进入洞穴"""
        try:
            entrance = random.choice(['A', 'B'])
            self.peggyEntranceEdit.setText(f"入口 {entrance}")
            self.log(f"Peggy 从入口 {entrance} 进入洞穴", "info")
            
            InfoBar.success(
                title="Peggy 进入",
                content=f"Peggy 从入口 {entrance} 进入",
                parent=self
            )
        except Exception as e:
            self.log(f"操作失败: {str(e)}", "error")
            MessageBox("错误", f"操作失败: {str(e)}", self).exec()
    
    def victorAsk(self):
        """Victor 要求从某个出口出来"""
        try:
            exit_choice = random.choice(['A', 'B'])
            self.victorExitEdit.setText(f"出口 {exit_choice}")
            self.log(f"Victor 要求 Peggy 从出口 {exit_choice} 出来", "info")
            
            InfoBar.success(
                title="Victor 要求",
                content=f"要求从出口 {exit_choice} 出来",
                parent=self
            )
        except Exception as e:
            self.log(f"操作失败: {str(e)}", "error")
            MessageBox("错误", f"操作失败: {str(e)}", self).exec()
    
    def verifySingle(self):
        """单次验证"""
        try:
            entrance_text = self.peggyEntranceEdit.text()
            exit_text = self.victorExitEdit.text()
            
            if not entrance_text or not exit_text:
                InfoBar.warning(
                    title="数据不完整",
                    content="请先完成 Peggy 进入和 Victor 要求",
                    parent=self
                )
                return
            
            entrance = entrance_text.split()[-1]
            exit_required = exit_text.split()[-1]
            
            # 判断是否成功
            if self.knows_password:
                # 知道密码，总能成功
                success = True
            else:
                # 不知道密码，只有入口和出口相同时才能成功
                success = (entrance == exit_required)
            
            # 更新统计
            self.verification_count += 1
            if success:
                self.success_count += 1
            
            # 显示结果
            if success:
                result = f"✅ 验证成功\n\nPeggy 从出口 {exit_required} 出来了！"
                self.log(f"验证 #{self.verification_count}: 成功", "success")
                InfoBar.success(
                    title="验证成功",
                    content="Peggy 成功从指定出口出来",
                    parent=self
                )
            else:
                result = f"❌ 验证失败\n\nPeggy 无法从出口 {exit_required} 出来！"
                self.log(f"验证 #{self.verification_count}: 失败", "error")
                InfoBar.error(
                    title="验证失败",
                    content="Peggy 无法从指定出口出来",
                    parent=self
                )
            
            self.singleResultEdit.setPlainText(result)
            self.updateStats()
            
        except Exception as e:
            self.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    def verifyBatch(self):
        """批量验证"""
        try:
            count_text = self.batchCountEdit.text()
            if not count_text:
                InfoBar.warning(
                    title="请输入验证次数",
                    content="请输入1-1000之间的数字",
                    parent=self
                )
                return
            
            count = int(count_text)
            if count <= 0 or count > 1000:
                InfoBar.warning(
                    title="验证次数无效",
                    content="验证次数必须在1-1000之间",
                    parent=self
                )
                return
            
            self.log(f"开始批量验证 {count} 次...", "info")
            
            batch_success = 0
            for i in range(count):
                if self.knows_password:
                    # 知道密码，总能成功
                    success = True
                else:
                    # 不知道密码，50%概率成功
                    success = (random.randint(0, 1) == 0)
                
                if success:
                    batch_success += 1
                
                self.verification_count += 1
                self.success_count += success
            
            # 显示结果
            batch_rate = (batch_success / count) * 100
            result = (
                f"批量验证完成\n\n"
                f"验证次数: {count}\n"
                f"成功次数: {batch_success}\n"
                f"失败次数: {count - batch_success}\n"
                f"成功率: {batch_rate:.1f}%"
            )
            
            self.batchResultEdit.setPlainText(result)
            self.updateStats()
            
            self.log(f"批量验证完成: {batch_success}/{count} 成功", "success")
            
            InfoBar.success(
                title="批量验证完成",
                content=f"成功率: {batch_rate:.1f}%",
                parent=self
            )
            
        except ValueError:
            InfoBar.error(
                title="输入错误",
                content="请输入有效的数字",
                parent=self
            )
        except Exception as e:
            self.log(f"批量验证失败: {str(e)}", "error")
            MessageBox("错误", f"批量验证失败: {str(e)}", self).exec()
    
    def updateStats(self):
        """更新统计信息"""
        self.totalCountEdit.setText(str(self.verification_count))
        self.successCountEdit.setText(str(self.success_count))
        
        if self.verification_count > 0:
            rate = (self.success_count / self.verification_count) * 100
            self.successRateEdit.setText(f"{rate:.1f}%")
            
            # 生成结论
            if rate >= 95:
                conclusion = (
                    f"✅ 高度可信\n\n"
                    f"成功率 {rate:.1f}% 非常高，可以确信 Peggy 知道密码。\n"
                    f"如果 Peggy 不知道密码，连续成功 {self.success_count} 次的概率仅为 "
                    f"{(0.5 ** self.success_count):.10f}（极低）。"
                )
                self.conclusionEdit.setPlainText(conclusion)
            elif rate >= 70:
                conclusion = (
                    f"⚠️ 较为可信\n\n"
                    f"成功率 {rate:.1f}% 较高，Peggy 可能知道密码。\n"
                    f"建议增加验证次数以提高可信度。"
                )
                self.conclusionEdit.setPlainText(conclusion)
            else:
                conclusion = (
                    f"❌ 不可信\n\n"
                    f"成功率 {rate:.1f}% 较低，接近随机猜测的 50%。\n"
                    f"Peggy 很可能不知道密码。"
                )
                self.conclusionEdit.setPlainText(conclusion)
        else:
            self.successRateEdit.setText("0%")
            self.conclusionEdit.clear()
    
    # ========== 清空功能 ==========
    
    def clearSingle(self):
        """清空单次验证"""
        self.peggyEntranceEdit.clear()
        self.victorExitEdit.clear()
        self.singleResultEdit.clear()
        self.log("已清空单次验证数据", "info")
    
    def clearBatch(self):
        """清空批量验证"""
        self.batchResultEdit.clear()
        self.log("已清空批量验证结果", "info")
    
    # ========== 日志功能 ==========
    
    def log(self, message, level='info'):
        """添加日志"""
        icons = {
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌'
        }
        colors = {
            'info': '#3b82f6',
            'success': '#10b981',
            'warning': '#f59e0b',
            'error': '#ef4444'
        }
        
        icon = icons.get(level, 'ℹ️')
        color = colors.get(level, '#3b82f6')
        
        self.logEdit.append(
            f"{icon} <span style='color: {color};'>{message}</span>"
        )
