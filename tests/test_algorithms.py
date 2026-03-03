#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
密码学算法功能测试
"""

import sys


def test_classical_ciphers():
    """测试古典密码"""
    print("\n" + "=" * 60)
    print("测试古典密码算法")
    print("=" * 60)
    
    results = []
    
    # 1. 凯撒密码
    try:
        from core.algorithms.classical.Caesar import Thread as CaesarThread
        thread = CaesarThread(None, "HELLO", 3, 0)
        cipher = thread.encrypt("HELLO", 3)
        plain = thread.decrypt(cipher, 3)
        success = (plain == "HELLO")
        print(f"{'✓' if success else '✗'} 凯撒密码: HELLO -> {cipher} -> {plain}")
        results.append(success)
    except Exception as e:
        print(f"✗ 凯撒密码失败: {e}")
        results.append(False)
    
    # 2. 维吉尼亚密码
    try:
        from core.algorithms.classical.Vigenere import Thread as VigenereThread
        thread = VigenereThread(None, "HELLO", "KEY", 0)
        cipher = thread.encrypt("HELLO", "KEY")
        plain = thread.decrypt(cipher, "KEY")
        success = (plain == "HELLO")
        print(f"{'✓' if success else '✗'} 维吉尼亚密码: HELLO -> {cipher} -> {plain}")
        results.append(success)
    except Exception as e:
        print(f"✗ 维吉尼亚密码失败: {e}")
        results.append(False)
    
    return all(results) if results else False


def test_symmetric_ciphers():
    """测试对称加密算法"""
    print("\n" + "=" * 60)
    print("测试对称加密算法")
    print("=" * 60)
    
    results = []
    
    # AES
    try:
        from core.algorithms.symmetric import AES
        print("✓ AES模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ AES模块导入失败: {e}")
        results.append(False)
    
    # DES
    try:
        from core.algorithms.symmetric import DES
        print("✓ DES模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ DES模块导入失败: {e}")
        results.append(False)
    
    # SM4
    try:
        from core.algorithms.symmetric import SM4
        print("✓ SM4模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ SM4模块导入失败: {e}")
        results.append(False)
    
    return all(results) if results else False


def test_asymmetric_ciphers():
    """测试非对称加密算法"""
    print("\n" + "=" * 60)
    print("测试非对称加密算法")
    print("=" * 60)
    
    results = []
    
    # RSA
    try:
        from core.algorithms.asymmetric import RSA
        print("✓ RSA模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ RSA模块导入失败: {e}")
        results.append(False)
    
    # ECC
    try:
        from core.algorithms.asymmetric import ECC
        print("✓ ECC模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ ECC模块导入失败: {e}")
        results.append(False)
    
    # SM2
    try:
        from core.algorithms.asymmetric import SM2
        print("✓ SM2模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ SM2模块导入失败: {e}")
        results.append(False)
    
    return all(results) if results else False


def test_hash_algorithms():
    """测试哈希算法"""
    print("\n" + "=" * 60)
    print("测试哈希算法")
    print("=" * 60)
    
    results = []
    
    # MD5
    try:
        from core.algorithms.hash import MD5
        print("✓ MD5模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ MD5模块导入失败: {e}")
        results.append(False)
    
    # SHA1
    try:
        from core.algorithms.hash import SHA1
        print("✓ SHA1模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ SHA1模块导入失败: {e}")
        results.append(False)
    
    # SHA256
    try:
        from core.algorithms.hash import SHA256
        print("✓ SHA256模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ SHA256模块导入失败: {e}")
        results.append(False)
    
    # SM3
    try:
        from core.algorithms.hash import SM3
        print("✓ SM3模块导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ SM3模块导入失败: {e}")
        results.append(False)
    
    return all(results) if results else False


def test_ui_components():
    """测试UI组件"""
    print("\n" + "=" * 60)
    print("测试UI组件")
    print("=" * 60)
    
    results = []
    
    try:
        from ui.main_window import CryptographyWidget
        print("✓ 主窗口导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ 主窗口导入失败: {e}")
        results.append(False)
    
    try:
        from ui.widgets import classical
        print("✓ 古典密码UI组件导入成功")
        results.append(True)
    except Exception as e:
        print(f"✗ 古典密码UI组件导入失败: {e}")
        results.append(False)
    
    return all(results) if results else False


def main():
    """主测试函数"""
    print("\n╔" + "=" * 58 + "╗")
    print("║" + " " * 15 + "密码学算法功能测试" + " " * 15 + "║")
    print("╚" + "=" * 58 + "╝")
    
    test_results = {
        "古典密码": test_classical_ciphers(),
        "对称加密": test_symmetric_ciphers(),
        "非对称加密": test_asymmetric_ciphers(),
        "哈希算法": test_hash_algorithms(),
        "UI组件": test_ui_components(),
    }
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    for name, passed in test_results.items():
        status = "✓ 通过" if passed else "✗ 失败"
        print(f"{name:15s}: {status}")
    
    passed_count = sum(1 for p in test_results.values() if p)
    total_count = len(test_results)
    
    print("=" * 60)
    print(f"总计: {passed_count}/{total_count} 测试通过")
    print("=" * 60 + "\n")
    
    return passed_count == total_count


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
