"""
修复批量更新后的语法错误
主要问题：删除self.widgets_dict = {}时删除了换行符
"""
import os
import re

# 需要修复的文件列表
FILES_TO_FIX = [
    'ui/widgets/Hill_ui.py',
    'ui/widgets/Playfair_ui.py',
    'ui/widgets/Enigma_ui.py',
    'ui/widgets/Monoalphabetic_Cipher_ui.py',
    'ui/widgets/Frequency_Analysis_ui.py',
    'ui/widgets/DES_ui.py',
    'ui/widgets/SM4_ui.py',
    'ui/widgets/SIMON_ui.py',
    'ui/widgets/SPECK_ui.py',
    'ui/widgets/Block_Mode_ui.py',
    'ui/widgets/RC4_ui.py',
    'ui/widgets/ZUC_ui.py',
    'ui/widgets/SEAL_ui.py',
    'ui/widgets/Crypto_1_ui.py',
    'ui/widgets/MD5_ui.py',
    'ui/widgets/SHA1_ui.py',
    'ui/widgets/SHA256_ui.py',
    'ui/widgets/SHA3_ui.py',
    'ui/widgets/SM3_ui.py',
    'ui/widgets/HMAC_MD5_ui.py',
    'ui/widgets/AES_CBC_MAC_ui.py',
    'ui/widgets/Hash_Reverse_ui.py',
    'ui/widgets/CRT_ui.py',
    'ui/widgets/Euclidean_ui.py',
    'ui/widgets/Password_System_ui.py',
]

def fix_file(filepath):
    """修复单个文件的语法错误"""
    print(f"Checking: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # 修复：在self.groups_config之前添加换行
        # 匹配模式：任何字符后直接跟着self.groups_config
        content = re.sub(
            r'([^\n])\s+(self\.groups_config\s*=)',
            r'\1\n        \n        \2',
            content
        )
        
        # 如果有变化，写回文件
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"  ✓ Fixed: {filepath}")
            return True
        else:
            print(f"  - No changes needed: {filepath}")
            return False
            
    except Exception as e:
        print(f"  ✗ Error: {filepath} - {e}")
        return False

def main():
    """主函数"""
    print("=" * 60)
    print("修复语法错误脚本")
    print("=" * 60)
    print(f"\n总共需要检查 {len(FILES_TO_FIX)} 个文件\n")
    
    fixed_count = 0
    
    for filepath in FILES_TO_FIX:
        if os.path.exists(filepath):
            if fix_file(filepath):
                fixed_count += 1
        else:
            print(f"  ✗ File not found: {filepath}")
    
    print("\n" + "=" * 60)
    print(f"完成！修复了 {fixed_count}/{len(FILES_TO_FIX)} 个文件")
    print("=" * 60)

if __name__ == '__main__':
    main()
