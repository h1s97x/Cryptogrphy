"""
百万富翁问题 - Fluent Design 版本

演示场景：
两个百万富翁（王和李）想知道谁更富有，但都不想透露自己的具体财富。
使用安全多方计算协议解决这个问题。

协议步骤：
1. 生成资产和密钥：王和李各有资产（1-9百万），王生成RSA密钥对
2. 李加密：李选择随机数X，用王的公钥加密，生成C列表
3. 王解密：王解密C列表，生成素数P和D列表
4. 李验证：李计算X mod P，与D列表比较，得出谁更富有

注：本版本使用简化的RSA实现，仅用于教学演示
"""

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    InfoBar, MessageBox, FluentIcon as FIF
)

import random
import math


def is_prime(num):
    """判断是否为素数"""
    if num < 2:
        return False
    for i in range(2, math.floor(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True


def gcd(a, b):
    """求最大公约数"""
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def get_prime_arr(max_num):
    """获取小于等于指定数的素数数组"""
    prime_array = []
    for i in range(11, max_num):
        if is_prime(i):
            prime_array.append(i)
    return prime_array


def build_key():
    """生成RSA密钥对"""
    prime_arr = get_prime_arr(50)
    p = random.choice(prime_arr)
    
    # 保证p和q不为同一个数
    while True:
        q = random.choice(prime_arr)
        if p != q:
            break
    
    n = p * q
    s = (p - 1) * (q - 1)
    
    # 找出与s互质的e
    while True:
        e = random.randint(2, n - 1)
        if gcd(e, s) == 1 and e < n:
            break
    
    # 找出d使得 (e*d) mod s = 1
    for k in range(1, 100000000):
        x = (e * k) % s
        if x == 1:
            d = k
            break
    
    return n, e, d


def rsa_encrypt(content, public_key):
    """RSA加密"""
    n, e = public_key
    return pow(content, e) % n


def rsa_decrypt(ciphertext, private_key):
    """RSA解密"""
    n, d = private_key
    return pow(ciphertext, d) % n


class MillionaireWidget(ScrollArea):
    """百万富翁问题演示界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("millionaireWidget")
        self.wang_assets = 0
        self.li_assets = 0
        self.public_key = None
        self.private_key = None
        self.random_x = 0
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
        title = TitleLabel("百万富翁问题")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "安全多方计算协议演示：两个百万富翁想知道谁更富有，但都不想透露具体财富。\n"
            "使用RSA加密和模运算实现隐私保护的财富比较。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 1. 初始化卡片
        self.initCard = self.createInitCard()
        layout.addWidget(self.initCard)
        
        # 2. 李的操作卡片
        self.liCard = self.createLiCard()
        layout.addWidget(self.liCard)
        
        # 3. 王的操作卡片
        self.wangCard = self.createWangCard()
        layout.addWidget(self.wangCard)
        
        # 4. 验证卡片
        self.verifyCard = self.createVerifyCard()
        layout.addWidget(self.verifyCard)
        
        # 5. 日志卡片
        self.logCard = self.createLogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        self.log("百万富翁问题演示已加载", "success")
    
    def createInitCard(self):
        """创建初始化卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📊 步骤1：初始化数据")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 资产
        assetsLayout = QHBoxLayout()
        
        wangLayout = QVBoxLayout()
        wangLabel = BodyLabel("王的资产（百万）")
        wangLayout.addWidget(wangLabel)
        self.wangAssetsEdit = LineEdit()
        self.wangAssetsEdit.setReadOnly(True)
        self.wangAssetsEdit.setPlaceholderText("点击生成...")
        wangLayout.addWidget(self.wangAssetsEdit)
        assetsLayout.addLayout(wangLayout)
        
        liLayout = QVBoxLayout()
        liLabel = BodyLabel("李的资产（百万）")
        liLayout.addWidget(liLabel)
        self.liAssetsEdit = LineEdit()
        self.liAssetsEdit.setReadOnly(True)
        self.liAssetsEdit.setPlaceholderText("点击生成...")
        liLayout.addWidget(self.liAssetsEdit)
        assetsLayout.addLayout(liLayout)
        
        layout.addLayout(assetsLayout)
        
        # 密钥
        keyLabel = BodyLabel("王的RSA密钥对")
        layout.addWidget(keyLabel)
        
        pubKeyLabel = BodyLabel("公钥 (n, e)")
        layout.addWidget(pubKeyLabel)
        self.publicKeyEdit = LineEdit()
        self.publicKeyEdit.setReadOnly(True)
        self.publicKeyEdit.setPlaceholderText("点击生成...")
        layout.addWidget(self.publicKeyEdit)
        
        privKeyLabel = BodyLabel("私钥 (n, d)")
        layout.addWidget(privKeyLabel)
        self.privateKeyEdit = LineEdit()
        self.privateKeyEdit.setReadOnly(True)
        self.privateKeyEdit.setPlaceholderText("点击生成...")
        layout.addWidget(self.privateKeyEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.genAssetsBtn = PrimaryPushButton(FIF.MONEY, "生成资产")
        self.genAssetsBtn.clicked.connect(self.generateAssets)
        self.genKeyBtn = PrimaryPushButton(FIF.FINGERPRINT, "生成密钥")
        self.genKeyBtn.clicked.connect(self.generateKey)
        self.clearInitBtn = PushButton(FIF.DELETE, "清空")
        self.clearInitBtn.clicked.connect(self.clearInit)
        
        btnLayout.addWidget(self.genAssetsBtn)
        btnLayout.addWidget(self.genKeyBtn)
        btnLayout.addWidget(self.clearInitBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createLiCard(self):
        """创建李的操作卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("👤 步骤2：李的操作")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 随机数X
        xLabel = BodyLabel("随机数 X")
        layout.addWidget(xLabel)
        self.randomXEdit = LineEdit()
        self.randomXEdit.setReadOnly(True)
        self.randomXEdit.setPlaceholderText("点击生成...")
        layout.addWidget(self.randomXEdit)
        
        # 加密后的K
        kLabel = BodyLabel("加密后的 K = Encrypt(X)")
        layout.addWidget(kLabel)
        self.encryptedKEdit = LineEdit()
        self.encryptedKEdit.setReadOnly(True)
        self.encryptedKEdit.setPlaceholderText("加密结果...")
        layout.addWidget(self.encryptedKEdit)
        
        # C列表
        cLabel = BodyLabel("C 列表 = [K-j+1, K-j+2, ..., K-j+10]")
        layout.addWidget(cLabel)
        self.cListEdit = TextEdit()
        self.cListEdit.setReadOnly(True)
        self.cListEdit.setMaximumHeight(60)
        self.cListEdit.setPlaceholderText("C列表...")
        layout.addWidget(self.cListEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.genXBtn = PrimaryPushButton(FIF.SYNC, "生成随机数X")
        self.genXBtn.clicked.connect(self.generateX)
        self.encryptBtn = PushButton(FIF.LOCK, "加密并生成C列表")
        self.encryptBtn.clicked.connect(self.encryptAndGenerateC)
        self.clearLiBtn = PushButton(FIF.DELETE, "清空")
        self.clearLiBtn.clicked.connect(self.clearLi)
        
        btnLayout.addWidget(self.genXBtn)
        btnLayout.addWidget(self.encryptBtn)
        btnLayout.addWidget(self.clearLiBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createWangCard(self):
        """创建王的操作卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("👤 步骤3：王的操作")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 解密后的列表
        decryptLabel = BodyLabel("解密后的列表")
        layout.addWidget(decryptLabel)
        self.decryptListEdit = TextEdit()
        self.decryptListEdit.setReadOnly(True)
        self.decryptListEdit.setMaximumHeight(60)
        self.decryptListEdit.setPlaceholderText("解密结果...")
        layout.addWidget(self.decryptListEdit)
        
        # 素数P
        pLabel = BodyLabel("素数 P (小于X)")
        layout.addWidget(pLabel)
        self.primeEdit = LineEdit()
        self.primeEdit.setReadOnly(True)
        self.primeEdit.setPlaceholderText("素数P...")
        layout.addWidget(self.primeEdit)
        
        # D列表
        dLabel = BodyLabel("D 列表 = [decrypt[i] mod P]")
        layout.addWidget(dLabel)
        self.dListEdit = TextEdit()
        self.dListEdit.setReadOnly(True)
        self.dListEdit.setMaximumHeight(60)
        self.dListEdit.setPlaceholderText("D列表...")
        layout.addWidget(self.dListEdit)
        
        # D_new列表
        dNewLabel = BodyLabel("D_new 列表（根据王的资产调整）")
        layout.addWidget(dNewLabel)
        self.dNewListEdit = TextEdit()
        self.dNewListEdit.setReadOnly(True)
        self.dNewListEdit.setMaximumHeight(60)
        self.dNewListEdit.setPlaceholderText("D_new列表...")
        layout.addWidget(self.dNewListEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.decryptBtn = PrimaryPushButton(FIF.UNLOCK, "解密C列表")
        self.decryptBtn.clicked.connect(self.decryptC)
        self.genPDBtn = PushButton(FIF.EDIT, "生成P和D")
        self.genPDBtn.clicked.connect(self.generatePD)
        self.genDNewBtn = PushButton(FIF.SEND, "生成D_new")
        self.genDNewBtn.clicked.connect(self.generateDNew)
        self.clearWangBtn = PushButton(FIF.DELETE, "清空")
        self.clearWangBtn.clicked.connect(self.clearWang)
        
        btnLayout.addWidget(self.decryptBtn)
        btnLayout.addWidget(self.genPDBtn)
        btnLayout.addWidget(self.genDNewBtn)
        btnLayout.addWidget(self.clearWangBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createVerifyCard(self):
        """创建验证卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("✅ 步骤4：李验证结果")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # X mod P
        xmodpLabel = BodyLabel("X mod P")
        layout.addWidget(xmodpLabel)
        self.xmodpEdit = LineEdit()
        self.xmodpEdit.setReadOnly(True)
        self.xmodpEdit.setPlaceholderText("计算结果...")
        layout.addWidget(self.xmodpEdit)
        
        # 验证结果
        resultLabel = BodyLabel("比较结果")
        layout.addWidget(resultLabel)
        self.resultEdit = TextEdit()
        self.resultEdit.setReadOnly(True)
        self.resultEdit.setMaximumHeight(80)
        self.resultEdit.setPlaceholderText("验证结果...")
        layout.addWidget(self.resultEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.calcXmodPBtn = PrimaryPushButton(FIF.CALCULATOR, "计算 X mod P")
        self.calcXmodPBtn.clicked.connect(self.calculateXmodP)
        self.verifyBtn = PushButton(FIF.ACCEPT, "验证")
        self.verifyBtn.clicked.connect(self.verify)
        self.clearVerifyBtn = PushButton(FIF.DELETE, "清空")
        self.clearVerifyBtn.clicked.connect(self.clearVerify)
        
        btnLayout.addWidget(self.calcXmodPBtn)
        btnLayout.addWidget(self.verifyBtn)
        btnLayout.addWidget(self.clearVerifyBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
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
    
    def generateAssets(self):
        """生成资产"""
        try:
            self.wang_assets = random.randint(1, 9)
            self.li_assets = random.randint(1, 9)
            
            self.wangAssetsEdit.setText(str(self.wang_assets))
            self.liAssetsEdit.setText(str(self.li_assets))
            
            self.log(f"王的资产: {self.wang_assets} 百万", "success")
            self.log(f"李的资产: {self.li_assets} 百万", "success")
            
            InfoBar.success(
                title="生成成功",
                content=f"王: {self.wang_assets}百万, 李: {self.li_assets}百万",
                parent=self
            )
        except Exception as e:
            self.log(f"生成资产失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
    
    def generateKey(self):
        """生成RSA密钥对"""
        try:
            self.log("正在生成RSA密钥对...", "info")
            
            n, e, d = build_key()
            self.public_key = (n, e)
            self.private_key = (n, d)
            
            self.publicKeyEdit.setText(f"({n}, {e})")
            self.privateKeyEdit.setText(f"({n}, {d})")
            
            self.log(f"公钥: (n={n}, e={e})", "success")
            self.log(f"私钥: (n={n}, d={d})", "success")
            
            InfoBar.success(
                title="生成成功",
                content="RSA密钥对已生成",
                parent=self
            )
        except Exception as e:
            self.log(f"生成密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
    
    def generateX(self):
        """生成随机数X"""
        try:
            self.random_x = random.randint(1, 100)
            self.randomXEdit.setText(str(self.random_x))
            
            self.log(f"生成随机数 X = {self.random_x}", "success")
            
            InfoBar.success(
                title="生成成功",
                content=f"随机数 X = {self.random_x}",
                parent=self
            )
        except Exception as e:
            self.log(f"生成随机数失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
    
    def encryptAndGenerateC(self):
        """加密X并生成C列表"""
        try:
            if self.public_key is None:
                InfoBar.warning(
                    title="密钥未生成",
                    content="请先生成RSA密钥对",
                    parent=self
                )
                return
            
            if self.random_x == 0:
                InfoBar.warning(
                    title="随机数未生成",
                    content="请先生成随机数X",
                    parent=self
                )
                return
            
            if self.li_assets == 0:
                InfoBar.warning(
                    title="资产未生成",
                    content="请先生成资产",
                    parent=self
                )
                return
            
            # 加密X
            k = rsa_encrypt(self.random_x, self.public_key)
            self.encryptedKEdit.setText(str(k))
            self.log(f"加密 X 得到 K = {k}", "info")
            
            # 生成C列表
            c = k - self.li_assets
            c_list = [c + i + 1 for i in range(10)]
            self.cListEdit.setPlainText(str(c_list))
            
            self.log(f"C 列表: {c_list}", "success")
            
            InfoBar.success(
                title="加密成功",
                content="已生成C列表",
                parent=self
            )
        except Exception as e:
            self.log(f"加密失败: {str(e)}", "error")
            MessageBox("错误", f"加密失败: {str(e)}", self).exec()
    
    def decryptC(self):
        """解密C列表"""
        try:
            if self.private_key is None:
                InfoBar.warning(
                    title="密钥未生成",
                    content="请先生成RSA密钥对",
                    parent=self
                )
                return
            
            c_text = self.cListEdit.toPlainText()
            if not c_text:
                InfoBar.warning(
                    title="C列表为空",
                    content="请先生成C列表",
                    parent=self
                )
                return
            
            # 解析C列表
            c_list = eval(c_text)
            
            # 解密
            decrypt_list = [rsa_decrypt(c, self.private_key) for c in c_list]
            self.decryptListEdit.setPlainText(str(decrypt_list))
            
            self.log(f"解密列表: {decrypt_list}", "success")
            
            InfoBar.success(
                title="解密成功",
                content="已解密C列表",
                parent=self
            )
        except Exception as e:
            self.log(f"解密失败: {str(e)}", "error")
            MessageBox("错误", f"解密失败: {str(e)}", self).exec()
    
    def generatePD(self):
        """生成素数P和D列表"""
        try:
            if self.random_x == 0:
                InfoBar.warning(
                    title="随机数未生成",
                    content="请先生成随机数X",
                    parent=self
                )
                return
            
            decrypt_text = self.decryptListEdit.toPlainText()
            if not decrypt_text:
                InfoBar.warning(
                    title="解密列表为空",
                    content="请先解密C列表",
                    parent=self
                )
                return
            
            # 解析解密列表
            decrypt_list = eval(decrypt_text)
            
            # 生成素数P（小于X）
            while True:
                p = random.randint(2, self.random_x - 1)
                if is_prime(p):
                    break
            
            self.primeEdit.setText(str(p))
            self.log(f"生成素数 P = {p}", "success")
            
            # 生成D列表
            d_list = [val % p for val in decrypt_list]
            self.dListEdit.setPlainText(str(d_list))
            
            self.log(f"D 列表: {d_list}", "success")
            
            InfoBar.success(
                title="生成成功",
                content=f"素数 P = {p}",
                parent=self
            )
        except Exception as e:
            self.log(f"生成P和D失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
    
    def generateDNew(self):
        """生成D_new列表"""
        try:
            if self.wang_assets == 0:
                InfoBar.warning(
                    title="资产未生成",
                    content="请先生成资产",
                    parent=self
                )
                return
            
            d_text = self.dListEdit.toPlainText()
            if not d_text:
                InfoBar.warning(
                    title="D列表为空",
                    content="请先生成D列表",
                    parent=self
                )
                return
            
            # 解析D列表
            d_list = eval(d_text)
            
            # 生成D_new列表（从王的资产位置开始，每个元素+1）
            d_new = d_list.copy()
            for i in range(self.wang_assets, 10):
                d_new[i] += 1
            
            self.dNewListEdit.setPlainText(str(d_new))
            
            self.log(f"D_new 列表: {d_new}", "success")
            self.log(f"（从位置 {self.wang_assets} 开始，每个元素+1）", "info")
            
            InfoBar.success(
                title="生成成功",
                content="已生成D_new列表",
                parent=self
            )
        except Exception as e:
            self.log(f"生成D_new失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
    
    def calculateXmodP(self):
        """计算 X mod P"""
        try:
            if self.random_x == 0:
                InfoBar.warning(
                    title="随机数未生成",
                    content="请先生成随机数X",
                    parent=self
                )
                return
            
            p_text = self.primeEdit.text()
            if not p_text:
                InfoBar.warning(
                    title="素数P未生成",
                    content="请先生成素数P",
                    parent=self
                )
                return
            
            p = int(p_text)
            xmodp = self.random_x % p
            
            self.xmodpEdit.setText(str(xmodp))
            self.log(f"X mod P = {self.random_x} mod {p} = {xmodp}", "success")
            
            InfoBar.success(
                title="计算成功",
                content=f"X mod P = {xmodp}",
                parent=self
            )
        except Exception as e:
            self.log(f"计算失败: {str(e)}", "error")
            MessageBox("错误", f"计算失败: {str(e)}", self).exec()
    
    def verify(self):
        """验证结果"""
        try:
            if self.li_assets == 0:
                InfoBar.warning(
                    title="资产未生成",
                    content="请先生成资产",
                    parent=self
                )
                return
            
            xmodp_text = self.xmodpEdit.text()
            if not xmodp_text:
                InfoBar.warning(
                    title="X mod P未计算",
                    content="请先计算 X mod P",
                    parent=self
                )
                return
            
            d_new_text = self.dNewListEdit.toPlainText()
            if not d_new_text:
                InfoBar.warning(
                    title="D_new列表为空",
                    content="请先生成D_new列表",
                    parent=self
                )
                return
            
            xmodp = int(xmodp_text)
            d_new = eval(d_new_text)
            
            # 验证：比较 D_new[j-1] 和 X mod P
            j = self.li_assets
            
            self.log(f"李的资产位置: {j}", "info")
            self.log(f"D_new[{j-1}] = {d_new[j-1]}", "info")
            self.log(f"X mod P = {xmodp}", "info")
            
            if d_new[j - 1] == xmodp:
                result = f"✅ 王 >= 李\n\n王的资产: {self.wang_assets} 百万\n李的资产: {self.li_assets} 百万\n\n王更富有或一样富有！"
                self.log("验证结果: 王 >= 李", "success")
                InfoBar.success(
                    title="验证完成",
                    content="王更富有或一样富有",
                    parent=self
                )
            else:
                result = f"✅ 王 < 李\n\n王的资产: {self.wang_assets} 百万\n李的资产: {self.li_assets} 百万\n\n李更富有！"
                self.log("验证结果: 王 < 李", "success")
                InfoBar.success(
                    title="验证完成",
                    content="李更富有",
                    parent=self
                )
            
            self.resultEdit.setPlainText(result)
            
        except Exception as e:
            self.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    # ========== 清空功能 ==========
    
    def clearInit(self):
        """清空初始化区域"""
        self.wangAssetsEdit.clear()
        self.liAssetsEdit.clear()
        self.publicKeyEdit.clear()
        self.privateKeyEdit.clear()
        self.wang_assets = 0
        self.li_assets = 0
        self.public_key = None
        self.private_key = None
        self.log("已清空初始化数据", "info")
    
    def clearLi(self):
        """清空李的操作区域"""
        self.randomXEdit.clear()
        self.encryptedKEdit.clear()
        self.cListEdit.clear()
        self.random_x = 0
        self.log("已清空李的操作数据", "info")
    
    def clearWang(self):
        """清空王的操作区域"""
        self.decryptListEdit.clear()
        self.primeEdit.clear()
        self.dListEdit.clear()
        self.dNewListEdit.clear()
        self.log("已清空王的操作数据", "info")
    
    def clearVerify(self):
        """清空验证区域"""
        self.xmodpEdit.clear()
        self.resultEdit.clear()
        self.log("已清空验证数据", "info")
    
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
