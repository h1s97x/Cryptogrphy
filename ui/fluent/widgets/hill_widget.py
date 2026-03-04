"""
Hill 密码算法界面 - Fluent Design 版本
"""

import numpy
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QFileDialog
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CaptionLabel,
    InfoBar, InfoBarPosition, MessageBox
)

from ui.fluent.components.algorithm_card import KeyCard, EncryptCard, DecryptCard, LogCard
from core.algorithms.classical.Hill import Thread as HillThread
import infrastructure.Path as PathUtils


class HillWidget(ScrollArea):
    """Hill 密码算法界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("hillWidget")
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
        title = TitleLabel("Hill 密码")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "Hill密码是一种基于线性代数的多字母替换密码，"
            "使用矩阵运算进行加密和解密。密钥是一个可逆矩阵。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 密钥配置卡片
        self.keyCard = KeyCard()
        self.keyCard.keyEdit.setPlainText("8 6 9 5\n6 9 5 10\n5 8 4 9\n10 6 11 4")
        layout.addWidget(self.keyCard)
        
        # 加密卡片
        self.encryptCard = EncryptCard()
        self.encryptCard.plaintextEdit.setPlainText("hill")
        layout.addWidget(self.encryptCard)
        
        # 解密卡片
        self.decryptCard = DecryptCard()
        layout.addWidget(self.decryptCard)
        
        # 日志卡片
        self.logCard = LogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        # 初始日志
        self.logCard.log("Hill 算法已加载", "success")
    
    def connectSignals(self):
        """连接信号"""
        # 密钥卡片
        self.keyCard.generateBtn.clicked.connect(self.generateKey)
        self.keyCard.importBtn.clicked.connect(self.importKey)
        
        # 加密卡片
        self.encryptCard.encryptBtn.clicked.connect(self.encrypt)
        self.encryptCard.copyBtn.clicked.connect(self.copyCiphertext)
        self.encryptCard.saveBtn.clicked.connect(self.saveCiphertext)
        self.encryptCard.clearBtn.clicked.connect(self.encryptCard.clear)
        
        # 解密卡片
        self.decryptCard.decryptBtn.clicked.connect(self.decrypt)
        self.decryptCard.copyBtn.clicked.connect(self.copyPlaintext)
        self.decryptCard.saveBtn.clicked.connect(self.savePlaintext)
    
    def generateKey(self):
        """生成密钥"""
        InfoBar.info(
            title="提示",
            content="密钥生成功能开发中...",
            parent=self
        )
        self.logCard.log("密钥生成功能开发中", "warning")
    
    def importKey(self):
        """导入密钥文件"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "选择密钥文件",
                "",
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    key = f.read()
                self.keyCard.setKey(key)
                self.logCard.log(f"已导入密钥文件: {file_path}", "success")
                InfoBar.success(
                    title="导入成功",
                    content="密钥文件已导入",
                    parent=self
                )
        except Exception as e:
            self.logCard.log(f"导入密钥失败: {str(e)}", "error")
            MessageBox("错误", f"导入密钥失败: {str(e)}", self).exec()
    
    def validateKey(self, key):
        """验证密钥"""
        try:
            # 检查是否全为正整数
            key_str = key.replace("\n", " ").replace(" ", "")
            if not key_str.isdigit():
                raise ValueError("密钥必须是正整数矩阵")
            
            # 检查是否为方阵
            key_lines = [line for line in key.split('\n') if line.strip()]
            key_row = len(key_lines)
            
            for line in key_lines:
                if len(line.split()) != key_row:
                    raise ValueError("密钥必须是方阵")
            
            # 检查矩阵是否可逆
            key_ints = list(map(int, key.split()))
            key_matrix = numpy.array(key_ints).reshape(key_row, key_row)
            
            if numpy.linalg.det(key_matrix) == 0:
                raise ValueError("密钥矩阵不可逆")
            
            return True, key_row
        except Exception as e:
            return False, str(e)
    
    def encrypt(self):
        """加密"""
        try:
            self.logCard.log("开始加密...", "info")
            
            # 获取密钥
            key = self.keyCard.getKey()
            valid, result = self.validateKey(key)
            if not valid:
                raise ValueError(f"密钥验证失败: {result}")
            
            # 获取明文
            plaintext = self.encryptCard.getPlaintext()
            if not plaintext:
                raise ValueError("明文不能为空")
            
            # 检查明文中是否有汉字
            for ch in plaintext:
                if '\u4e00' <= ch <= '\u9fff':
                    raise ValueError("明文不能包含汉字")
            
            self.logCard.log(f"明文: {plaintext}", "info")
            self.logCard.log(f"密钥:\n{key}", "info")
            
            # 创建加密线程
            thread = HillThread(self, plaintext, key, 0)
            thread.final_result.connect(self.onEncryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def onEncryptFinished(self, ciphertext):
        """加密完成"""
        self.encryptCard.setCiphertext(ciphertext)
        self.decryptCard.setCiphertext(ciphertext)
        self.logCard.log(f"密文: {ciphertext}", "success")
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
            
            # 获取密钥
            key = self.keyCard.getKey()
            valid, result = self.validateKey(key)
            if not valid:
                raise ValueError(f"密钥验证失败: {result}")
            
            key_row = result
            
            # 获取密文
            ciphertext = self.decryptCard.getCiphertext()
            if not ciphertext:
                raise ValueError("密文不能为空")
            
            # 检查密文中是否有汉字
            for ch in ciphertext:
                if '\u4e00' <= ch <= '\u9fff':
                    raise ValueError("密文不能包含汉字")
            
            # 检查密文长度
            cipher_letters = [ch for ch in ciphertext if ch.isalpha()]
            if len(cipher_letters) % key_row != 0:
                raise ValueError(f"密文长度必须是密钥矩阵行数({key_row})的整数倍")
            
            self.logCard.log(f"密文: {ciphertext}", "info")
            self.logCard.log(f"密钥:\n{key}", "info")
            
            # 创建解密线程
            thread = HillThread(self, ciphertext, key, 1)
            thread.final_result.connect(self.onDecryptFinished)
            thread.start()
            
        except Exception as e:
            self.logCard.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def onDecryptFinished(self, plaintext):
        """解密完成"""
        self.decryptCard.setPlaintext(plaintext)
        self.logCard.log(f"明文: {plaintext}", "success")
        self.logCard.log("解密完成", "success")
        
        InfoBar.success(
            title="解密成功",
            content="密文已成功解密",
            parent=self
        )
    
    def copyCiphertext(self):
        """复制密文"""
        from PyQt5.QtWidgets import QApplication
        ciphertext = self.encryptCard.getCiphertext()
        QApplication.clipboard().setText(ciphertext)
        InfoBar.success(title="已复制", content="密文已复制到剪贴板", parent=self)
        self.logCard.log("密文已复制到剪贴板", "info")
    
    def copyPlaintext(self):
        """复制明文"""
        from PyQt5.QtWidgets import QApplication
        plaintext = self.decryptCard.getPlaintext()
        QApplication.clipboard().setText(plaintext)
        InfoBar.success(title="已复制", content="明文已复制到剪贴板", parent=self)
        self.logCard.log("明文已复制到剪贴板", "info")
    
    def saveCiphertext(self):
        """保存密文"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "保存密文",
                "ciphertext.txt",
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.encryptCard.getCiphertext())
                self.logCard.log(f"密文已保存到: {file_path}", "success")
                InfoBar.success(title="保存成功", content="密文已保存", parent=self)
        except Exception as e:
            self.logCard.log(f"保存失败: {str(e)}", "error")
            MessageBox("错误", f"保存失败: {str(e)}", self).exec()
    
    def savePlaintext(self):
        """保存明文"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "保存明文",
                "plaintext.txt",
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.decryptCard.getPlaintext())
                self.logCard.log(f"明文已保存到: {file_path}", "success")
                InfoBar.success(title="保存成功", content="明文已保存", parent=self)
        except Exception as e:
            self.logCard.log(f"保存失败: {str(e)}", "error")
            MessageBox("错误", f"保存失败: {str(e)}", self).exec()
