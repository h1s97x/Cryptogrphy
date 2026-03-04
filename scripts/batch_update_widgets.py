"""
批量更新UI组件脚本
自动化将旧方式的组件更新为新的配置驱动方式
"""
import os
import re

# 需要更新的组件列表
WIDGETS_TO_UPDATE = [
    # 古典密码 (5个剩余)
    'ui/widgets/Hill_ui.py',
    'ui/widgets/Playfair_ui.py',
    'ui/widgets/Enigma_ui.py',
    'ui/widgets/Monoalphabetic_Cipher_ui.py',
    'ui/widgets/Frequency_Analysis_ui.py',
    
    # 对称加密 (10个)
    'ui/widgets/AES_ui.py',
    'ui/widgets/DES_ui.py',
    'ui/widgets/SM4_ui.py',
    'ui/widgets/SIMON_ui.py',
    'ui/widgets/SPECK_ui.py',
    'ui/widgets/Block_Mode_ui.py',
    'ui/widgets/RC4_ui.py',
    'ui/widgets/ZUC_ui.py',
    'ui/widgets/SEAL_ui.py',
    'ui/widgets/Crypto_1_ui.py',
    
    # 哈希算法 (8个)
    'ui/widgets/MD5_ui.py',
    'ui/widgets/SHA1_ui.py',
    'ui/widgets/SHA256_ui.py',
    'ui/widgets/SHA3_ui.py',
    'ui/widgets/SM3_ui.py',
    'ui/widgets/HMAC_MD5_ui.py',
    'ui/widgets/AES_CBC_MAC_ui.py',
    'ui/widgets/Hash_Reverse_ui.py',
    
    # 数学基础 (2个剩余)
    'ui/widgets/CRT_ui.py',
    'ui/widgets/Euclidean_ui.py',
    
    # 其他 (1个)
    'ui/widgets/Password_System_ui.py',
]

def update_imports(content):
    """更新导入语句"""
    # 添加KeyGroup和Key到导入
    if 'KeyGroup' not in content and 'Key' not in content:
        content = content.replace(
            'from ui.main_window import Button, PlainTextEdit, Group, ErrorType',
            'from ui.main_window import Button, PlainTextEdit, Group, ErrorType, KeyGroup, Key'
        )
    return content

def update_init_method(content):
    """更新__init__方法"""
    # 替换旧式初始化
    content = re.sub(
        r'CryptographyWidget\.__init__\(self\)',
        'super().__init__()',
        content
    )
    
    # 移除手动初始化widgets_dict
    content = re.sub(
        r'\s+self\.widgets_dict = \{\}\n',
        '',
        content
    )
    
    return content

def update_logging_calls(content):
    """更新日志调用"""
    # 替换 self.logging.log() 为 self.log_message()
    content = re.sub(
        r'self\.logging\.log\(',
        'self.log_message(',
        content
    )
    
    # 替换 self.logging.log_error() 为 self.logging_error()
    content = re.sub(
        r'self\.logging\.log_error\(',
        'self.logging_error(',
        content
    )
    
    return content

def update_widget_access(content):
    """更新组件访问方式"""
    # 这个需要根据具体情况判断
    # KeyGroup中的组件使用.text()
    # Group中的组件使用.get_text()
    # 这部分需要手动检查
    return content

def process_file(filepath):
    """处理单个文件"""
    print(f"Processing: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # 应用所有更新
        content = update_imports(content)
        content = update_init_method(content)
        content = update_logging_calls(content)
        
        # 如果有变化，写回文件
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"  ✓ Updated: {filepath}")
            return True
        else:
            print(f"  - No changes: {filepath}")
            return False
            
    except Exception as e:
        print(f"  ✗ Error: {filepath} - {e}")
        return False

def main():
    """主函数"""
    print("=" * 60)
    print("批量更新UI组件脚本")
    print("=" * 60)
    print(f"\n总共需要更新 {len(WIDGETS_TO_UPDATE)} 个组件\n")
    
    updated_count = 0
    
    for filepath in WIDGETS_TO_UPDATE:
        if os.path.exists(filepath):
            if process_file(filepath):
                updated_count += 1
        else:
            print(f"  ✗ File not found: {filepath}")
    
    print("\n" + "=" * 60)
    print(f"完成！更新了 {updated_count}/{len(WIDGETS_TO_UPDATE)} 个文件")
    print("=" * 60)
    print("\n注意：")
    print("1. 需要手动检查KeyGroup中的组件访问方式（.text() vs .get_text()）")
    print("2. 需要手动将Key配置从Group移到KeyGroup")
    print("3. 建议逐个测试更新后的组件")

if __name__ == '__main__':
    main()
