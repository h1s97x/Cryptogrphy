#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
清理旧目录结构脚本
删除已废弃的旧目录和兼容层文件
"""

import os
import shutil
from pathlib import Path

# 要删除的目录
OLD_DIRECTORIES = [
    'BlockCipher',
    'ClassicCrypto',
    'Hash',
    'PublicKeyCryptography',
    'StreamCipher',
    'MathematicalBasis',
    'CryptographicProtocol',
]

# 要删除的兼容层文件
OLD_COMPATIBILITY_FILES = [
    'BlockCipher.py',
    'ClassicCrypto.py',
    'Hash.py',
    'PublicKeyCryptography.py',
    'StreamCipher.py',
    'MathematicalBasis.py',
]


def check_directory_empty(directory):
    """检查目录是否为空或只包含 __init__.py 和 __pycache__"""
    if not os.path.exists(directory):
        return True
    
    for root, dirs, files in os.walk(directory):
        # 过滤掉 __pycache__
        dirs[:] = [d for d in dirs if d != '__pycache__']
        
        # 检查文件
        meaningful_files = [f for f in files if f not in ['__init__.py', '__init__.pyc']]
        if meaningful_files:
            return False
    
    return True


def analyze_old_structure():
    """分析旧结构的状态"""
    print("\n" + "=" * 60)
    print("分析旧目录结构")
    print("=" * 60)
    
    analysis = {
        'empty_dirs': [],
        'non_empty_dirs': [],
        'missing_dirs': [],
        'files_exist': [],
        'files_missing': [],
    }
    
    # 检查目录
    for directory in OLD_DIRECTORIES:
        if not os.path.exists(directory):
            analysis['missing_dirs'].append(directory)
            print(f"⊘ {directory:30s} - 不存在")
        elif check_directory_empty(directory):
            analysis['empty_dirs'].append(directory)
            print(f"○ {directory:30s} - 空目录（可安全删除）")
        else:
            analysis['non_empty_dirs'].append(directory)
            print(f"● {directory:30s} - 包含文件（需要检查）")
    
    print()
    
    # 检查兼容层文件
    for filepath in OLD_COMPATIBILITY_FILES:
        if os.path.exists(filepath):
            analysis['files_exist'].append(filepath)
            print(f"● {filepath:30s} - 存在")
        else:
            analysis['files_missing'].append(filepath)
            print(f"⊘ {filepath:30s} - 不存在")
    
    return analysis


def list_directory_contents(directory, max_depth=2):
    """列出目录内容"""
    print(f"\n目录内容: {directory}")
    print("-" * 60)
    
    for root, dirs, files in os.walk(directory):
        level = root.replace(directory, '').count(os.sep)
        if level >= max_depth:
            continue
        
        indent = '  ' * level
        print(f"{indent}{os.path.basename(root)}/")
        
        sub_indent = '  ' * (level + 1)
        for file in files:
            if file != '__init__.pyc' and not file.endswith('.pyc'):
                print(f"{sub_indent}{file}")


def confirm_deletion():
    """确认删除操作"""
    print("\n" + "=" * 60)
    print("⚠ 警告：即将删除旧目录结构")
    print("=" * 60)
    print("\n这将删除以下内容:")
    print("\n目录:")
    for directory in OLD_DIRECTORIES:
        if os.path.exists(directory):
            print(f"  - {directory}/")
    
    print("\n文件:")
    for filepath in OLD_COMPATIBILITY_FILES:
        if os.path.exists(filepath):
            print(f"  - {filepath}")
    
    print("\n" + "=" * 60)
    response = input("\n确认删除？(yes/no): ").strip().lower()
    return response in ['yes', 'y']


def backup_reminder():
    """提醒备份"""
    print("\n" + "=" * 60)
    print("⚠ 重要提醒")
    print("=" * 60)
    print("\n在删除之前，请确保:")
    print("1. 已运行 update_imports.py 更新所有导入")
    print("2. 已运行测试确认功能正常")
    print("3. 已创建 Git 备份:")
    print("   git add .")
    print("   git commit -m 'Backup before cleanup'")
    print("   git tag backup-before-cleanup")
    print("\n如果出现问题，可以回滚:")
    print("   git reset --hard backup-before-cleanup")
    print("=" * 60)
    
    response = input("\n已完成备份？(yes/no): ").strip().lower()
    return response in ['yes', 'y']


def delete_old_structure(dry_run=True):
    """删除旧目录结构"""
    deleted_dirs = []
    deleted_files = []
    failed = []
    
    mode = "模拟" if dry_run else "实际"
    print(f"\n{mode}删除操作:")
    print("=" * 60)
    
    # 删除目录
    for directory in OLD_DIRECTORIES:
        if os.path.exists(directory):
            try:
                if not dry_run:
                    shutil.rmtree(directory)
                deleted_dirs.append(directory)
                print(f"✓ 删除目录: {directory}/")
            except Exception as e:
                failed.append((directory, str(e)))
                print(f"✗ 删除失败: {directory}/ - {e}")
        else:
            print(f"⊘ 跳过（不存在）: {directory}/")
    
    # 删除文件
    for filepath in OLD_COMPATIBILITY_FILES:
        if os.path.exists(filepath):
            try:
                if not dry_run:
                    os.remove(filepath)
                deleted_files.append(filepath)
                print(f"✓ 删除文件: {filepath}")
            except Exception as e:
                failed.append((filepath, str(e)))
                print(f"✗ 删除失败: {filepath} - {e}")
        else:
            print(f"⊘ 跳过（不存在）: {filepath}")
    
    return deleted_dirs, deleted_files, failed


def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("密码学平台 - 旧结构清理工具")
    print("=" * 60)
    
    # 1. 分析旧结构
    analysis = analyze_old_structure()
    
    # 2. 如果有非空目录，显示内容
    if analysis['non_empty_dirs']:
        print("\n" + "=" * 60)
        print("⚠ 警告：发现非空目录")
        print("=" * 60)
        for directory in analysis['non_empty_dirs']:
            list_directory_contents(directory)
        
        print("\n请检查这些目录是否包含重要文件！")
        response = input("继续删除？(yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("\n已取消操作")
            return
    
    # 3. 提醒备份
    if not backup_reminder():
        print("\n请先创建备份，然后重新运行此脚本")
        return
    
    # 4. 模拟删除
    print("\n" + "=" * 60)
    print("步骤 1: 模拟删除（预览）")
    print("=" * 60)
    deleted_dirs, deleted_files, failed = delete_old_structure(dry_run=True)
    
    if failed:
        print("\n⚠ 发现问题:")
        for item, error in failed:
            print(f"  - {item}: {error}")
        print("\n请解决这些问题后重试")
        return
    
    # 5. 确认并实际删除
    if not confirm_deletion():
        print("\n已取消操作")
        return
    
    print("\n" + "=" * 60)
    print("步骤 2: 实际删除")
    print("=" * 60)
    deleted_dirs, deleted_files, failed = delete_old_structure(dry_run=False)
    
    # 6. 总结
    print("\n" + "=" * 60)
    print("清理总结")
    print("=" * 60)
    print(f"✓ 删除目录: {len(deleted_dirs)} 个")
    print(f"✓ 删除文件: {len(deleted_files)} 个")
    print(f"✗ 失败: {len(failed)} 个")
    
    if failed:
        print("\n失败项:")
        for item, error in failed:
            print(f"  - {item}: {error}")
    
    print("\n" + "=" * 60)
    print("下一步:")
    print("1. 运行测试: python test_project.py")
    print("2. 启动应用: python main.py")
    print("3. 如果一切正常，提交更改:")
    print("   git add .")
    print("   git commit -m 'Remove old directory structure'")
    print("\n如果出现问题，回滚:")
    print("   git reset --hard backup-before-cleanup")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    main()
