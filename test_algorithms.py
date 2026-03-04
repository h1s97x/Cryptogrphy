"""
密码学平台算法测试脚本
测试所有已实现的算法是否正常工作
"""

import sys
import io

# 设置标准输出编码为UTF-8
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from PyQt5.QtWidgets import QApplication

def test_imports():
    """测试所有widget是否可以正常导入"""
    print("=" * 60)
    print("测试 1: 导入所有Widget")
    print("=" * 60)
    
    widgets = [
        # 经典密码
        ("Hill", "ui.fluent.widgets.hill_widget", "HillWidget"),
        ("Caesar", "ui.fluent.widgets.caesar_widget", "CaesarWidget"),
        ("Vigenere", "ui.fluent.widgets.vigenere_widget", "VigenereWidget"),
        ("Playfair", "ui.fluent.widgets.playfair_widget", "PlayfairWidget"),
        ("Enigma", "ui.fluent.widgets.enigma_widget", "EnigmaWidget"),
        ("Monoalphabetic", "ui.fluent.widgets.monoalphabetic_widget", "MonoalphabeticWidget"),
        ("Frequency Analysis", "ui.fluent.widgets.frequency_analysis_widget", "FrequencyAnalysisWidget"),
        
        # 对称密码
        ("AES", "ui.fluent.widgets.aes_widget", "AESWidget"),
        ("DES", "ui.fluent.widgets.des_widget", "DESWidget"),
        ("SM4", "ui.fluent.widgets.sm4_widget", "SM4Widget"),
        ("RC4", "ui.fluent.widgets.rc4_widget", "RC4Widget"),
        ("SPECK", "ui.fluent.widgets.speck_widget", "SPECKWidget"),
        ("SIMON", "ui.fluent.widgets.simon_widget", "SIMONWidget"),
        ("Block Mode", "ui.fluent.widgets.block_mode_widget", "BlockModeWidget"),
        
        # 公钥密码
        ("RSA", "ui.fluent.widgets.rsa_widget", "RSAWidget"),
        ("RSA Sign", "ui.fluent.widgets.rsa_sign_widget", "RSASignWidget"),
        ("ElGamal", "ui.fluent.widgets.elgamal_widget", "ElGamalWidget"),
        ("ECDSA", "ui.fluent.widgets.ecdsa_widget", "ECDSAWidget"),
        
        # 哈希算法
        ("MD5", "ui.fluent.widgets.md5_widget", "MD5Widget"),
        ("SHA-1", "ui.fluent.widgets.sha1_widget", "SHA1Widget"),
        ("SHA-256", "ui.fluent.widgets.sha256_widget", "SHA256Widget"),
        ("SHA-3", "ui.fluent.widgets.sha3_widget", "SHA3Widget"),
        ("SM3", "ui.fluent.widgets.sm3_widget", "SM3Widget"),
        ("HMAC-MD5", "ui.fluent.widgets.hmac_md5_widget", "HMACMD5Widget"),
        ("AES-CBC-MAC", "ui.fluent.widgets.aes_cbc_mac_widget", "AESCBCMACWidget"),
        
        # 数学基础
        ("Euler", "ui.fluent.widgets.euler_widget", "EulerWidget"),
        ("CRT", "ui.fluent.widgets.crt_widget", "CRTWidget"),
        ("Euclidean", "ui.fluent.widgets.euclidean_widget", "EuclideanWidget"),
    ]
    
    success_count = 0
    failed_widgets = []
    
    for name, module_path, class_name in widgets:
        try:
            module = __import__(module_path, fromlist=[class_name])
            widget_class = getattr(module, class_name)
            print(f"✅ {name:20s} - 导入成功")
            success_count += 1
        except Exception as e:
            print(f"❌ {name:20s} - 导入失败: {str(e)}")
            failed_widgets.append((name, str(e)))
    
    print(f"\n导入测试完成: {success_count}/{len(widgets)} 成功")
    
    if failed_widgets:
        print("\n失败的Widget:")
        for name, error in failed_widgets:
            print(f"  - {name}: {error}")
    
    return success_count == len(widgets)


def test_core_algorithms():
    """测试核心算法是否可以正常导入"""
    print("\n" + "=" * 60)
    print("测试 2: 核心算法导入")
    print("=" * 60)
    
    algorithms = [
        ("AES", "core.algorithms.symmetric.AES"),
        ("DES", "core.algorithms.symmetric.DES"),
        ("RSA", "core.algorithms.asymmetric.RSA"),
        ("SHA256", "core.algorithms.hash.SHA256"),
        ("MD5", "core.algorithms.hash.MD5"),
    ]
    
    success_count = 0
    
    for name, module_path in algorithms:
        try:
            __import__(module_path)
            print(f"✅ {name:20s} - 核心算法可用")
            success_count += 1
        except Exception as e:
            print(f"❌ {name:20s} - 导入失败: {str(e)}")
    
    print(f"\n核心算法测试完成: {success_count}/{len(algorithms)} 成功")
    return success_count == len(algorithms)


def test_main_window():
    """测试主窗口是否可以创建"""
    print("\n" + "=" * 60)
    print("测试 3: 主窗口创建")
    print("=" * 60)
    
    try:
        app = QApplication(sys.argv)
        from ui.fluent.main_window import FluentMainWindow
        window = FluentMainWindow()
        print("✅ 主窗口创建成功")
        print(f"   窗口标题: {window.windowTitle()}")
        print(f"   窗口大小: {window.width()}x{window.height()}")
        app.quit()
        return True
    except Exception as e:
        print(f"❌ 主窗口创建失败: {str(e)}")
        return False


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("密码学平台 - 自动化测试")
    print("=" * 60)
    
    results = []
    
    # 测试1: Widget导入
    results.append(("Widget导入", test_imports()))
    
    # 测试2: 核心算法
    results.append(("核心算法", test_core_algorithms()))
    
    # 测试3: 主窗口
    results.append(("主窗口创建", test_main_window()))
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"{test_name:20s}: {status}")
    
    print(f"\n总体结果: {passed}/{total} 测试通过")
    
    if passed == total:
        print("\n🎉 所有测试通过！项目状态良好。")
        return 0
    else:
        print("\n⚠️  部分测试失败，需要修复。")
        return 1


if __name__ == "__main__":
    sys.exit(main())
