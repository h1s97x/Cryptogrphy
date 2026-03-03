#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
自动更新导入路径脚本
将旧的导入路径更新为新的 core/algorithms 结构
"""

import os
import re
from pathlib import Path

# 导入映射规则
IMPORT_MAPPINGS = [
    # 古典密码
    (r'from ClassicCrypto\.Caesar import (\w+)', r'from core.algorithms.classical.Caesar import Thread as \1'),
    (r'from ClassicCrypto\.Vigenere import (\w+)', r'from core.algorithms.classical.Vigenere import Thread as \1'),
    (r'from ClassicCrypto\.Hill import (\w+)', r'from core.algorithms.classical.Hill import Thread as \1'),
    (r'from ClassicCrypto\.Playfair import (\w+)', r'from core.algorithms.classical.Playfair import Thread as \1'),
    (r'from ClassicCrypto\.Enigma import (\w+)', r'from core.algorithms.classical.Enigma import Thread as \1'),
    (r'from ClassicCrypto\.Monoalphabetic_Cipher import (\w+)', r'from core.algorithms.classical.Monoalphabetic_Cipher import Thread as \1'),
    (r'from ClassicCrypto\.Frequency_Analysis import (\w+)', r'from core.algorithms.classical.Frequency_Analysis import Thread as \1'),
    
    # 对称加密（分组密码）
    (r'from BlockCipher\.AES import (\w+)', r'from core.algorithms.symmetric.AES import Thread as \1'),
    (r'from BlockCipher\.DES import (\w+)', r'from core.algorithms.symmetric.DES import Thread as \1'),
    (r'from BlockCipher\.SM4 import (\w+)', r'from core.algorithms.symmetric.SM4 import Thread as \1'),
    (r'from BlockCipher\.SIMON import (\w+)', r'from core.algorithms.symmetric.SIMON import Thread as \1'),
    (r'from BlockCipher\.SPECK import (\w+)', r'from core.algorithms.symmetric.SPECK import Thread as \1'),
    (r'from BlockCipher\.Block_Mode import (\w+)', r'from core.algorithms.symmetric.Block_Mode import Thread as \1'),
    
    # 流密码
    (r'from StreamCipher\.RC4 import (\w+)', r'from core.algorithms.symmetric.RC4 import Thread as \1'),
    (r'from StreamCipher\.ZUC import (\w+)', r'from core.algorithms.symmetric.ZUC import Thread as \1'),
    (r'from StreamCipher\.SEAL import (\w+)', r'from core.algorithms.symmetric.SEAL import Thread as \1'),
    (r'from StreamCipher\.Crypto_1 import (\w+)', r'from core.algorithms.symmetric.Crypto_1 import Thread as \1'),
    
    # 哈希算法
    (r'from Hash\.MD5 import (\w+)', r'from core.algorithms.hash.MD5 import Thread as \1'),
    (r'from Hash\.SHA1 import (\w+)', r'from core.algorithms.hash.SHA1 import Thread as \1'),
    (r'from Hash\.SHA256 import (\w+)', r'from core.algorithms.hash.SHA256 import Thread as \1'),
    (r'from Hash\.SHA3 import (\w+)', r'from core.algorithms.hash.SHA3 import Thread as \1'),
    (r'from Hash\.SM3 import (\w+)', r'from core.algorithms.hash.SM3 import Thread as \1'),
    (r'from Hash\.HMAC_MD5 import (\w+)', r'from core.algorithms.hash.HMAC_MD5 import Thread as \1'),
    (r'from Hash\.AES_CBC_MAC import (\w+)', r'from core.algorithms.hash.AES_CBC_MAC import Thread as \1'),
    (r'from Hash\.Hash_Reverse import (\w+)', r'from core.algorithms.hash.Hash_Reverse import Thread as \1'),
    
    # 非对称加密
    (r'from PublicKeyCryptography\.RSA import (\w+)', r'from core.algorithms.asymmetric.RSA import Thread as \1'),
    (r'from PublicKeyCryptography\.RSA_Sign import (\w+)', r'from core.algorithms.asymmetric.RSA_Sign import Thread as \1'),
    (r'from PublicKeyCryptography\.ECC import (\w+)', r'from core.algorithms.asymmetric.ECC import Thread as \1'),
    (r'from PublicKeyCryptography\.ECDSA import (\w+)', r'from core.algorithms.asymmetric.ECDSA import Thread as \1'),
    (r'from PublicKeyCryptography\.ElGamal import (\w+)', r'from core.algorithms.asymmetric.ElGamal import Thread as \1'),
    (r'from PublicKeyCryptography\.SM2 import (\w+)', r'from core.algorithms.asymmetric.SM2 import Thread as \1'),
    (r'from PublicKeyCryptography\.SM2_Sign import (\w+)', r'from core.algorithms.asymmetric.SM2_Sign import Thread as \1'),
    
    # 数学基础
    (r'from MathematicalBasis\.CRT import (\w+)', r'from core.algorithms.mathematical.CRT import Thread as \1'),
    (r'from MathematicalBasis\.Euclidean import (\w+)', r'from core.algorithms.mathematical.Euclidean import Thread as \1'),
    (r'from MathematicalBasis\.Euler import (\w+)', r'from core.algorithms.mathematical.Euler import Thread as \1'),
]


def update_file_imports(filepath):
    """更新单个文件的导入语句"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  ⚠ 读取失败: {e}")
        return False
    
    original_content = content
    changes = []
    
    # 应用所有映射规则
    for old_pattern, new_pattern in IMPORT_MAPPINGS:
        matches = re.findall(old_pattern, content)
        if matches:
            content = re.sub(old_pattern, new_pattern, content)
            for match in matches:
                old_import = old_pattern.replace(r'(\w+)', match).replace('\\', '')
                new_import = new_pattern.replace(r'\1', match).replace('\\', '')
                changes.append((old_import, new_import))
    
    # 如果有更改，写回文件
    if content != original_content:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return changes
        except Exception as e:
            print(f"  ⚠ 写入失败: {e}")
            return False
    
    return None


def scan_and_update_directory(directory):
    """扫描目录并更新所有Python文件"""
    directory = Path(directory)
    updated_files = []
    unchanged_files = []
    failed_files = []
    
    print(f"\n扫描目录: {directory}")
    print("=" * 60)
    
    for filepath in directory.rglob('*.py'):
        # 跳过 __pycache__ 和测试脚本
        if '__pycache__' in str(filepath) or filepath.name in ['update_imports.py', 'test_project.py', 'test_algorithms.py']:
            continue
        
        relative_path = filepath.relative_to(directory)
        result = update_file_imports(filepath)
        
        if result is False:
            failed_files.append(relative_path)
            print(f"✗ {relative_path} - 失败")
        elif result is None:
            unchanged_files.append(relative_path)
        elif result:
            updated_files.append((relative_path, result))
            print(f"✓ {relative_path}")
            for old_imp, new_imp in result:
                print(f"  - {old_imp}")
                print(f"  + {new_imp}")
    
    return updated_files, unchanged_files, failed_files


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("密码学平台 - 导入路径自动更新工具")
    print("=" * 60)
    
    # 更新 ui/widgets 目录
    ui_updated, ui_unchanged, ui_failed = scan_and_update_directory('ui/widgets')
    
    # 打印总结
    print("\n" + "=" * 60)
    print("更新总结")
    print("=" * 60)
    print(f"✓ 已更新: {len(ui_updated)} 个文件")
    print(f"- 未改变: {len(ui_unchanged)} 个文件")
    print(f"✗ 失败: {len(ui_failed)} 个文件")
    
    if ui_updated:
        print("\n已更新的文件:")
        for filepath, _ in ui_updated:
            print(f"  - {filepath}")
    
    if ui_failed:
        print("\n失败的文件:")
        for filepath in ui_failed:
            print(f"  - {filepath}")
    
    print("\n" + "=" * 60)
    print("下一步:")
    print("1. 检查更新结果: git diff ui/widgets/")
    print("2. 运行测试: python test_project.py")
    print("3. 如果测试通过，删除旧目录")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    main()
