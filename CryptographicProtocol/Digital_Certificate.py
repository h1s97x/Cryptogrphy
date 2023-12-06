from PyQt5 import QtCore
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import Menu.CryptographicAlgorithm.PublicKeyCryptography.RSA.mm_rsa as mm_rsa
import datetime
from Util import Path


class KeyThread(QtCore.QThread):
    call_back = QtCore.pyqtSignal(tuple)

    def __init__(self, parent):
        super(KeyThread, self).__init__(parent)

    def run(self):
        keys = mm_rsa.newkeys(1024, shift_select=False)
        self.call_back.emit(keys)


class CAThread(QtCore.QThread):
    result = QtCore.pyqtSignal(object)

    def __init__(self, parent, cert_key, digit_key):
        super(CAThread, self).__init__(parent)
        self.public_key = rsa.RSAPublicNumbers(digit_key[0], digit_key[1])
        public_key = rsa.RSAPublicNumbers(cert_key[1].e, cert_key[1].n)
        self.private_key = rsa.RSAPrivateNumbers(cert_key[1].p, cert_key[1].q, cert_key[1].d, cert_key[1].exp1, cert_key[1].exp2, cert_key[1].coef, public_key)
        self.subject = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'CN'),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, 'Local'),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, 'Local'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Local Host'),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Local Host'),
        ])
        self.issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'CN'),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, 'Beijing'),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, 'Haidian'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'MathMagic Co.'),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'MathMagic Co.'),
        ])
        self.path = Path.MENU_DIRECTORY + '/CryptographicAlgorithm/CryptographicProtocol/Digital_Certificate/certificate.cer'

    def run(self):
        self.certificate()

    def certificate(self):
        cert = x509.CertificateBuilder().subject_name(self.subject) \
            .issuer_name(self.issuer) \
            .public_key(self.public_key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('192.168.0.1')]), critical=False, ) \
            .sign(self.private_key.private_key(), hashes.SHA256())
        with open(self.path, 'wb') as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.DER))
        self.result.emit(cert.signature)
