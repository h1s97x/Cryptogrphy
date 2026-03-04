"""
测试RSA和RSA_Sign修复
验证使用pycryptodome实现的RSA功能
"""
import sys
sys.path.insert(0, '.')

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QEventLoop
from core.algorithms.asymmetric.RSA import KeyThread, RsaThread
from core.algorithms.asymmetric.RSA_Sign import KeyThread as SignKeyThread, RsaSignThread

def test_rsa_key_generation():
    """测试RSA密钥生成"""
    print("测试RSA密钥生成...", end=" ")
    
    app = QApplication(sys.argv)
    loop = QEventLoop()
    
    result = {'keys': None}
    
    def on_key_generated(keys):
        result['keys'] = keys
        loop.quit()
    
    thread = KeyThread(None)
    thread.call_back.connect(on_key_generated)
    thread.start()
    
    loop.exec_()
    
    if result['keys'] and result['keys'][0] and result['keys'][1]:
        print("✓ 成功")
        return True
    else:
        print("✗ 失败")
        return False

def test_rsa_encryption():
    """测试RSA加密"""
    print("测试RSA加密...", end=" ")
    
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    
    loop = QEventLoop()
    
    # 先生成密钥
    keys_result = {'keys': None}
    
    def on_key_generated(keys):
        keys_result['keys'] = keys
        loop.quit()
    
    key_thread = KeyThread(None)
    key_thread.call_back.connect(on_key_generated)
    key_thread.start()
    loop.exec_()
    
    if not keys_result['keys'] or not keys_result['keys'][0]:
        print("✗ 密钥生成失败")
        return False
    
    # 测试加密
    encrypt_result = {'ciphertext': None}
    
    def on_encrypted(ciphertext):
        encrypt_result['ciphertext'] = ciphertext
        loop.quit()
    
    plaintext = "Hello RSA"
    encrypt_thread = RsaThread(None, plaintext, keys_result['keys'], 0)
    encrypt_thread.call_back.connect(on_encrypted)
    encrypt_thread.start()
    loop.exec_()
    
    if encrypt_result['ciphertext'] and encrypt_result['ciphertext'] != "Encrypt Failed":
        print("✓ 成功")
        return True
    else:
        print("✗ 失败")
        return False

def test_rsa_sign_key_generation():
    """测试RSA签名密钥生成"""
    print("测试RSA签名密钥生成...", end=" ")
    
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    
    loop = QEventLoop()
    
    result = {'keys': None}
    
    def on_key_generated(keys):
        result['keys'] = keys
        loop.quit()
    
    thread = SignKeyThread(None)
    thread.call_back.connect(on_key_generated)
    thread.start()
    
    loop.exec_()
    
    if result['keys'] and result['keys'][0] and result['keys'][1]:
        print("✓ 成功")
        return True
    else:
        print("✗ 失败")
        return False

def test_rsa_signature():
    """测试RSA签名"""
    print("测试RSA签名...", end=" ")
    
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    
    loop = QEventLoop()
    
    # 先生成密钥
    keys_result = {'keys': None}
    
    def on_key_generated(keys):
        keys_result['keys'] = keys
        loop.quit()
    
    key_thread = SignKeyThread(None)
    key_thread.call_back.connect(on_key_generated)
    key_thread.start()
    loop.exec_()
    
    if not keys_result['keys'] or not keys_result['keys'][1]:
        print("✗ 密钥生成失败")
        return False
    
    # 测试签名
    sign_result = {'signature': None}
    
    def on_signed(signature):
        sign_result['signature'] = signature
        loop.quit()
    
    message = "Hello RSA Signature"
    sign_thread = RsaSignThread(None, message, keys_result['keys'])
    sign_thread.call_back.connect(on_signed)
    sign_thread.start()
    loop.exec_()
    
    if sign_result['signature'] and sign_result['signature'] != "Sign Failed":
        print("✓ 成功")
        return True
    else:
        print("✗ 失败")
        return False

def main():
    """主测试函数"""
    print("="*60)
    print("RSA功能修复测试")
    print("="*60)
    print()
    
    tests = [
        ("RSA密钥生成", test_rsa_key_generation),
        ("RSA加密", test_rsa_encryption),
        ("RSA签名密钥生成", test_rsa_sign_key_generation),
        ("RSA签名", test_rsa_signature),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ 异常: {e}")
            failed += 1
    
    print()
    print("="*60)
    print(f"测试结果: {passed}/{len(tests)} 通过")
    print("="*60)
    
    if failed == 0:
        print("\n🎉 所有测试通过！")
        return 0
    else:
        print(f"\n⚠️ {failed}个测试失败")
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
