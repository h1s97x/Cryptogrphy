#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
密码学平台项目测试脚本
测试各个模块的导入和基本功能
"""

import sys
import traceback

def test_imports():
    """测试核心模块导入"""
    print("=" * 60)
    print("测试模块导入...")
    print("=" * 60)
    
    tests = [
        ("PyQt5", lambda: __import__('PyQt5')),
        ("PyQt5.QtWidgets", lambda: __import__('PyQt5.QtWidgets')),
        ("numpy", lambda: __import__('numpy')),
        ("cryptography", lambda: __import__('cryptography')),
        
        # 测试核心算法模块
        ("core.algorithms.classical.Caesar", lambda: __import__('core.algorithms.classical.Caesar')),
        ("core.algorithms.symmetric.AES", lambda: __import__('core.algorithms.symmetric.AES')),
        ("core.algorithms.asymmetric.RSA", lambda: __import__('core.algorithms.asymmetric.RSA')),
        ("core.algorithms.hash.SHA", lambda: __import__('core.algorithms.hash.SHA')),
        
        # 测试UI模块
        ("ui.main_window", lambda: __import__('ui.main_window')),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            test_func()
            print(f"✓ {name:50s} [通过]")
            passed += 1
        except Exception as e:
            print(f"✗ {name:50s} [失败]")
            print(f"  错误: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"导入测试结果: {passed} 通过, {failed} 失败")
    print("=" * 60 + "\n")
    
    return failed == 0


def test_caesar_cipher():
    """测试凯撒密码算法"""
    print("=" * 60)
    print("测试凯撒密码算法...")
    print("=" * 60)
    
    try:
        from core.algorithms.classical.Caesar import Thread
        
        # 创建一个简单的测试
        plaintext = "Hello World"
        key = 3
        
        # 注意：Thread需要parent参数，这里传None
        thread = Thread(None, plaintext, key, 0)
        
        # 直接调用加密方法
        ciphertext = thread.encrypt(plaintext, key)
        print(f"明文: {plaintext}")
        print(f"密钥: {key}")
        print(f"密文: {ciphertext}")
        
        # 测试解密
        decrypted = thread.decrypt(ciphertext, key)
        print(f"解密: {decrypted}")
        
        if decrypted == plaintext:
            print("✓ 凯撒密码测试通过")
            return True
        else:
            print("✗ 凯撒密码测试失败：解密结果不匹配")
            return False
            
    except Exception as e:
        print(f"✗ 凯撒密码测试失败")
        print(f"错误: {str(e)}")
        traceback.print_exc()
        return False


def test_project_structure():
    """测试项目结构"""
    print("=" * 60)
    print("检查项目结构...")
    print("=" * 60)
    
    import os
    
    required_dirs = [
        'core',
        'core/algorithms',
        'core/algorithms/classical',
        'core/algorithms/symmetric',
        'core/algorithms/asymmetric',
        'core/algorithms/hash',
        'ui',
        'ui/widgets',
        'infrastructure',
    ]
    
    all_exist = True
    for dir_path in required_dirs:
        exists = os.path.isdir(dir_path)
        status = "✓" if exists else "✗"
        print(f"{status} {dir_path}")
        if not exists:
            all_exist = False
    
    print("\n" + "=" * 60)
    if all_exist:
        print("项目结构检查通过")
    else:
        print("项目结构检查失败：部分目录缺失")
    print("=" * 60 + "\n")
    
    return all_exist


def main():
    """主测试函数"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 15 + "密码学平台项目测试" + " " * 15 + "║")
    print("╚" + "=" * 58 + "╝")
    print("\n")
    
    results = []
    
    # 运行各项测试
    results.append(("项目结构", test_project_structure()))
    results.append(("模块导入", test_imports()))
    results.append(("凯撒密码", test_caesar_cipher()))
    
    # 总结
    print("\n")
    print("=" * 60)
    print("测试总结")
    print("=" * 60)
    
    for name, passed in results:
        status = "✓ 通过" if passed else "✗ 失败"
        print(f"{name:20s}: {status}")
    
    total_passed = sum(1 for _, passed in results if passed)
    total_tests = len(results)
    
    print("=" * 60)
    print(f"总计: {total_passed}/{total_tests} 测试通过")
    print("=" * 60)
    print("\n")
    
    return total_passed == total_tests


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
