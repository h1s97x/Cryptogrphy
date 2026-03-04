#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""更新导入路径：ui.fluent -> ui"""

import os

def update_file(filepath):
    """更新单个文件的导入路径"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 替换所有ui.fluent为ui
        updated = content.replace('ui.', 'ui.')
        
        if updated != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(updated)
            print(f"✅ 更新: {filepath}")
            return True
        return False
    except Exception as e:
        print(f"❌ 错误 {filepath}: {e}")
        return False

def main():
    """主函数"""
    count = 0
    
    # 遍历所有Python文件
    for root, dirs, files in os.walk('.'):
        # 跳过特定目录
        if '.git' in root or '__pycache__' in root or '.pytest_cache' in root:
            continue
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                if update_file(filepath):
                    count += 1
    
    # 更新Markdown文件
    for root, dirs, files in os.walk('docs'):
        for file in files:
            if file.endswith('.md'):
                filepath = os.path.join(root, file)
                if update_file(filepath):
                    count += 1
    
    print(f"\n总共更新了 {count} 个文件")

if __name__ == '__main__':
    main()
