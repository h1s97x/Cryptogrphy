"""
数字证书 - Fluent Design 版本

演示场景：
数字证书是PKI（公钥基础设施）的核心组件，用于证明公钥的所有权。
CA（证书颁发机构）使用自己的私钥对用户的公钥和身份信息进行签名，生成数字证书。

协议步骤：
1. CA生成RSA密钥对（用于签发证书）
2. 用户生成RSA密钥对（模拟智能卡）
3. CA为用户颁发X.509数字证书
4. 验证证书的有效性（使用CA公钥验证签名）

注：本版本移除智能卡依赖，使用纯软件模拟
"""

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout
from qfluentwidgets import (
    ScrollArea, TitleLabel, BodyLabel, CardWidget,
    PrimaryPushButton, PushButton, TextEdit, LineEdit,
    InfoBar, MessageBox, FluentIcon as FIF
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
import datetime


def format_hex(data: bytes, max_len=100) -> str:
    """格式化十六进制数据"""
    hex_str = data.hex().upper()
    if len(hex_str) > max_len:
        return hex_str[:max_len] + "..."
    return hex_str


class CAKeyGenThread(QThread):
    """CA密钥生成线程"""
    finished = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
    
    def run(self):
        try:
            # 生成2048位RSA密钥
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.finished.emit(key)
        except Exception as e:
            self.finished.emit(None)


class UserKeyGenThread(QThread):
    """用户密钥生成线程"""
    finished = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
    
    def run(self):
        try:
            # 生成2048位RSA密钥
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.finished.emit(key)
        except Exception as e:
            self.finished.emit(None)


class CertGenThread(QThread):
    """证书生成线程"""
    finished = pyqtSignal(object)
    
    def __init__(self, ca_key, user_public_key):
        super().__init__()
        self.ca_key = ca_key
        self.user_public_key = user_public_key
    
    def run(self):
        try:
            # 构建证书主题（用户信息）
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Haidian"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "User Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com"),
            ])
            
            # 构建证书颁发者（CA信息）
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Haidian"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, "ca@example.com"),
            ])
            
            # 生成证书
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.user_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(self.ca_key, hashes.SHA256())
            
            self.finished.emit(cert)
        except Exception as e:
            self.finished.emit(None)


class DigitalCertificateWidget(ScrollArea):
    """数字证书演示界面"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("digitalCertificateWidget")
        self.ca_key = None
        self.user_key = None
        self.certificate = None
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
        title = TitleLabel("数字证书")
        layout.addWidget(title)
        
        # 描述
        desc = BodyLabel(
            "PKI公钥基础设施：CA使用私钥为用户的公钥签名，生成数字证书。\n"
            "证书包含用户身份信息、公钥、有效期等，可用CA公钥验证真伪。"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 1. CA密钥生成卡片
        self.caKeyCard = self.createCAKeyCard()
        layout.addWidget(self.caKeyCard)
        
        # 2. 用户密钥生成卡片
        self.userKeyCard = self.createUserKeyCard()
        layout.addWidget(self.userKeyCard)
        
        # 3. 证书颁发卡片
        self.certCard = self.createCertCard()
        layout.addWidget(self.certCard)
        
        # 4. 证书验证卡片
        self.verifyCard = self.createVerifyCard()
        layout.addWidget(self.verifyCard)
        
        # 5. 日志卡片
        self.logCard = self.createLogCard()
        layout.addWidget(self.logCard)
        
        layout.addStretch()
        
        self.log("数字证书演示已加载", "success")
    
    def createCAKeyCard(self):
        """创建CA密钥生成卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("🏛️ 步骤1：CA生成密钥对")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # CA公钥
        pubLabel = BodyLabel("CA公钥 (Public Key) - 2048位")
        layout.addWidget(pubLabel)
        self.caPublicKeyEdit = TextEdit()
        self.caPublicKeyEdit.setReadOnly(True)
        self.caPublicKeyEdit.setMaximumHeight(100)
        self.caPublicKeyEdit.setPlaceholderText("点击生成CA密钥...")
        layout.addWidget(self.caPublicKeyEdit)
        
        # CA私钥
        privLabel = BodyLabel("CA私钥 (Private Key) - 2048位")
        layout.addWidget(privLabel)
        self.caPrivateKeyEdit = TextEdit()
        self.caPrivateKeyEdit.setReadOnly(True)
        self.caPrivateKeyEdit.setMaximumHeight(100)
        self.caPrivateKeyEdit.setPlaceholderText("点击生成CA密钥...")
        layout.addWidget(self.caPrivateKeyEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.genCAKeyBtn = PrimaryPushButton(FIF.FINGERPRINT, "生成CA密钥")
        self.genCAKeyBtn.clicked.connect(self.generateCAKey)
        self.clearCAKeyBtn = PushButton(FIF.DELETE, "清空")
        self.clearCAKeyBtn.clicked.connect(self.clearCAKey)
        
        btnLayout.addWidget(self.genCAKeyBtn)
        btnLayout.addWidget(self.clearCAKeyBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createUserKeyCard(self):
        """创建用户密钥生成卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("👤 步骤2：用户生成密钥对")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 用户公钥
        pubLabel = BodyLabel("用户公钥 (Public Key) - 2048位")
        layout.addWidget(pubLabel)
        self.userPublicKeyEdit = TextEdit()
        self.userPublicKeyEdit.setReadOnly(True)
        self.userPublicKeyEdit.setMaximumHeight(100)
        self.userPublicKeyEdit.setPlaceholderText("点击生成用户密钥...")
        layout.addWidget(self.userPublicKeyEdit)
        
        # 用户私钥
        privLabel = BodyLabel("用户私钥 (Private Key) - 2048位")
        layout.addWidget(privLabel)
        self.userPrivateKeyEdit = TextEdit()
        self.userPrivateKeyEdit.setReadOnly(True)
        self.userPrivateKeyEdit.setMaximumHeight(100)
        self.userPrivateKeyEdit.setPlaceholderText("点击生成用户密钥...")
        layout.addWidget(self.userPrivateKeyEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.genUserKeyBtn = PrimaryPushButton(FIF.FINGERPRINT, "生成用户密钥")
        self.genUserKeyBtn.clicked.connect(self.generateUserKey)
        self.clearUserKeyBtn = PushButton(FIF.DELETE, "清空")
        self.clearUserKeyBtn.clicked.connect(self.clearUserKey)
        
        btnLayout.addWidget(self.genUserKeyBtn)
        btnLayout.addWidget(self.clearUserKeyBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createCertCard(self):
        """创建证书颁发卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("📜 步骤3：CA颁发证书")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 证书内容
        certLabel = BodyLabel("X.509证书 (DER编码)")
        layout.addWidget(certLabel)
        self.certEdit = TextEdit()
        self.certEdit.setReadOnly(True)
        self.certEdit.setMaximumHeight(150)
        self.certEdit.setPlaceholderText("点击颁发证书...")
        layout.addWidget(self.certEdit)
        
        # 证书信息
        infoLabel = BodyLabel("证书信息")
        layout.addWidget(infoLabel)
        self.certInfoEdit = TextEdit()
        self.certInfoEdit.setReadOnly(True)
        self.certInfoEdit.setMaximumHeight(120)
        self.certInfoEdit.setPlaceholderText("证书详细信息...")
        layout.addWidget(self.certInfoEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.issueCertBtn = PrimaryPushButton(FIF.CERTIFICATE, "颁发证书")
        self.issueCertBtn.clicked.connect(self.issueCertificate)
        self.clearCertBtn = PushButton(FIF.DELETE, "清空")
        self.clearCertBtn.clicked.connect(self.clearCert)
        
        btnLayout.addWidget(self.issueCertBtn)
        btnLayout.addWidget(self.clearCertBtn)
        btnLayout.addStretch()
        layout.addLayout(btnLayout)
        
        return card
    
    def createVerifyCard(self):
        """创建证书验证卡片"""
        card = CardWidget()
        layout = QVBoxLayout(card)
        layout.setSpacing(12)
        
        # 标题
        title = BodyLabel("✅ 步骤4：验证证书")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # 证书TBS（待签名部分）
        tbsLabel = BodyLabel("证书TBS (To Be Signed)")
        layout.addWidget(tbsLabel)
        self.tbsEdit = TextEdit()
        self.tbsEdit.setReadOnly(True)
        self.tbsEdit.setMaximumHeight(80)
        self.tbsEdit.setPlaceholderText("证书待签名部分...")
        layout.addWidget(self.tbsEdit)
        
        # 证书签名
        sigLabel = BodyLabel("证书签名 (Signature)")
        layout.addWidget(sigLabel)
        self.signatureEdit = TextEdit()
        self.signatureEdit.setReadOnly(True)
        self.signatureEdit.setMaximumHeight(80)
        self.signatureEdit.setPlaceholderText("CA的数字签名...")
        layout.addWidget(self.signatureEdit)
        
        # 验证结果
        resultLabel = BodyLabel("验证结果")
        layout.addWidget(resultLabel)
        self.verifyResultEdit = TextEdit()
        self.verifyResultEdit.setReadOnly(True)
        self.verifyResultEdit.setMaximumHeight(80)
        self.verifyResultEdit.setPlaceholderText("验证结果...")
        layout.addWidget(self.verifyResultEdit)
        
        # 按钮
        btnLayout = QHBoxLayout()
        self.extractBtn = PushButton(FIF.DOCUMENT, "提取证书数据")
        self.extractBtn.clicked.connect(self.extractCertData)
        self.verifyBtn = PrimaryPushButton(FIF.ACCEPT, "验证证书")
        self.verifyBtn.clicked.connect(self.verifyCertificate)
        self.clearVerifyBtn = PushButton(FIF.DELETE, "清空")
        self.clearVerifyBtn.clicked.connect(self.clearVerify)
        
        btnLayout.addWidget(self.extractBtn)
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
    
    def generateCAKey(self):
        """生成CA密钥对"""
        try:
            self.log("正在生成CA的2048位RSA密钥对...", "info")
            self.genCAKeyBtn.setEnabled(False)
            
            # 创建密钥生成线程
            self.caKeyGenThread = CAKeyGenThread()
            self.caKeyGenThread.finished.connect(self.onCAKeyGenFinished)
            self.caKeyGenThread.start()
            
        except Exception as e:
            self.log(f"生成CA密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
            self.genCAKeyBtn.setEnabled(True)
    
    def onCAKeyGenFinished(self, key):
        """CA密钥生成完成"""
        self.genCAKeyBtn.setEnabled(True)
        
        if key is None:
            self.log("生成CA密钥失败", "error")
            MessageBox("错误", "生成CA密钥失败", self).exec()
            return
        
        self.ca_key = key
        
        # 导出公钥和私钥（PEM格式）
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        self.caPublicKeyEdit.setPlainText(public_pem)
        self.caPrivateKeyEdit.setPlainText(private_pem)
        
        self.log("CA密钥对生成成功", "success")
        self.log(f"密钥长度: {key.key_size} 位", "info")
        
        InfoBar.success(
            title="生成成功",
            content="CA的2048位RSA密钥对已生成",
            parent=self
        )
    
    def generateUserKey(self):
        """生成用户密钥对"""
        try:
            self.log("正在生成用户的2048位RSA密钥对...", "info")
            self.genUserKeyBtn.setEnabled(False)
            
            # 创建密钥生成线程
            self.userKeyGenThread = UserKeyGenThread()
            self.userKeyGenThread.finished.connect(self.onUserKeyGenFinished)
            self.userKeyGenThread.start()
            
        except Exception as e:
            self.log(f"生成用户密钥失败: {str(e)}", "error")
            MessageBox("错误", f"生成失败: {str(e)}", self).exec()
            self.genUserKeyBtn.setEnabled(True)
    
    def onUserKeyGenFinished(self, key):
        """用户密钥生成完成"""
        self.genUserKeyBtn.setEnabled(True)
        
        if key is None:
            self.log("生成用户密钥失败", "error")
            MessageBox("错误", "生成用户密钥失败", self).exec()
            return
        
        self.user_key = key
        
        # 导出公钥和私钥（PEM格式）
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        self.userPublicKeyEdit.setPlainText(public_pem)
        self.userPrivateKeyEdit.setPlainText(private_pem)
        
        self.log("用户密钥对生成成功", "success")
        self.log(f"密钥长度: {key.key_size} 位", "info")
        
        InfoBar.success(
            title="生成成功",
            content="用户的2048位RSA密钥对已生成",
            parent=self
        )
    
    def issueCertificate(self):
        """颁发证书"""
        try:
            if self.ca_key is None:
                InfoBar.warning(
                    title="CA密钥未生成",
                    content="请先生成CA密钥对",
                    parent=self
                )
                return
            
            if self.user_key is None:
                InfoBar.warning(
                    title="用户密钥未生成",
                    content="请先生成用户密钥对",
                    parent=self
                )
                return
            
            self.log("正在颁发数字证书...", "info")
            self.issueCertBtn.setEnabled(False)
            
            # 创建证书生成线程
            self.certGenThread = CertGenThread(self.ca_key, self.user_key.public_key())
            self.certGenThread.finished.connect(self.onCertGenFinished)
            self.certGenThread.start()
            
        except Exception as e:
            self.log(f"颁发证书失败: {str(e)}", "error")
            MessageBox("错误", f"颁发失败: {str(e)}", self).exec()
            self.issueCertBtn.setEnabled(True)
    
    def onCertGenFinished(self, cert):
        """证书生成完成"""
        self.issueCertBtn.setEnabled(True)
        
        if cert is None:
            self.log("颁发证书失败", "error")
            MessageBox("错误", "颁发证书失败", self).exec()
            return
        
        self.certificate = cert
        
        # 导出证书（DER格式）
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_hex = format_hex(cert_der, 200)
        self.certEdit.setPlainText(cert_hex)
        
        # 显示证书信息
        cert_info = f"""主题: {cert.subject.rfc4514_string()}
颁发者: {cert.issuer.rfc4514_string()}
序列号: {cert.serial_number}
有效期: {cert.not_valid_before} 至 {cert.not_valid_after}
签名算法: {cert.signature_algorithm_oid._name}
"""
        self.certInfoEdit.setPlainText(cert_info)
        
        self.log("数字证书颁发成功", "success")
        self.log(f"证书序列号: {cert.serial_number}", "info")
        self.log(f"证书主题: {cert.subject.rfc4514_string()}", "info")
        
        InfoBar.success(
            title="颁发成功",
            content="X.509数字证书已颁发",
            parent=self
        )
    
    def extractCertData(self):
        """提取证书数据"""
        try:
            if self.certificate is None:
                InfoBar.warning(
                    title="证书未颁发",
                    content="请先颁发证书",
                    parent=self
                )
                return
            
            # 提取TBS（待签名部分）
            tbs_bytes = self.certificate.tbs_certificate_bytes
            tbs_hex = format_hex(tbs_bytes, 200)
            self.tbsEdit.setPlainText(tbs_hex)
            
            # 提取签名
            signature_bytes = self.certificate.signature
            signature_hex = format_hex(signature_bytes, 200)
            self.signatureEdit.setPlainText(signature_hex)
            
            self.log("证书数据提取成功", "success")
            self.log(f"TBS长度: {len(tbs_bytes)} 字节", "info")
            self.log(f"签名长度: {len(signature_bytes)} 字节", "info")
            
            InfoBar.success(
                title="提取成功",
                content="证书TBS和签名已提取",
                parent=self
            )
            
        except Exception as e:
            self.log(f"提取失败: {str(e)}", "error")
            MessageBox("错误", f"提取失败: {str(e)}", self).exec()
    
    def verifyCertificate(self):
        """验证证书"""
        try:
            if self.ca_key is None:
                InfoBar.warning(
                    title="CA密钥未生成",
                    content="请先生成CA密钥对",
                    parent=self
                )
                return
            
            if self.certificate is None:
                InfoBar.warning(
                    title="证书未颁发",
                    content="请先颁发证书",
                    parent=self
                )
                return
            
            self.log("正在验证证书...", "info")
            
            # 获取CA公钥
            ca_public_key = self.ca_key.public_key()
            
            # 获取证书的TBS和签名
            tbs_bytes = self.certificate.tbs_certificate_bytes
            signature_bytes = self.certificate.signature
            
            # 验证签名
            try:
                ca_public_key.verify(
                    signature_bytes,
                    tbs_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                
                result = """✅ 证书验证成功

验证步骤：
1. 提取证书的TBS（待签名部分）
2. 提取证书的签名
3. 使用CA公钥验证签名
4. 验证通过，证书真实有效

结论：
该证书确实由CA签发，未被篡改。
证书中的公钥属于证书主题所声明的实体。
"""
                
                self.verifyResultEdit.setPlainText(result)
                self.log("✅ 证书验证成功", "success")
                self.log("签名验证通过，证书真实有效", "success")
                
                InfoBar.success(
                    title="验证成功",
                    content="证书签名验证通过",
                    parent=self
                )
                
            except InvalidSignature:
                result = """❌ 证书验证失败

验证步骤：
1. 提取证书的TBS（待签名部分）
2. 提取证书的签名
3. 使用CA公钥验证签名
4. 验证失败，签名不匹配

结论：
证书可能被篡改，或者不是由该CA签发。
不应信任此证书。
"""
                
                self.verifyResultEdit.setPlainText(result)
                self.log("❌ 证书验证失败", "error")
                self.log("签名验证失败，证书可能被篡改", "error")
                
                InfoBar.error(
                    title="验证失败",
                    content="证书签名验证失败",
                    parent=self
                )
            
        except Exception as e:
            self.log(f"验证失败: {str(e)}", "error")
            MessageBox("错误", f"验证失败: {str(e)}", self).exec()
    
    # ========== 清空功能 ==========
    
    def clearCAKey(self):
        """清空CA密钥"""
        self.caPublicKeyEdit.clear()
        self.caPrivateKeyEdit.clear()
        self.ca_key = None
        self.log("已清空CA密钥", "info")
    
    def clearUserKey(self):
        """清空用户密钥"""
        self.userPublicKeyEdit.clear()
        self.userPrivateKeyEdit.clear()
        self.user_key = None
        self.log("已清空用户密钥", "info")
    
    def clearCert(self):
        """清空证书"""
        self.certEdit.clear()
        self.certInfoEdit.clear()
        self.certificate = None
        self.log("已清空证书", "info")
    
    def clearVerify(self):
        """清空验证数据"""
        self.tbsEdit.clear()
        self.signatureEdit.clear()
        self.verifyResultEdit.clear()
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
