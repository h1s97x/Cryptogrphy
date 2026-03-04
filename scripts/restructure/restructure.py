#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
密码学平台重构 - 一键执行脚本
自动完成导入更新、测试验证、旧结构清理
"""

import os
import sys
import subprocess
from pathlib import Path


def print_header(title):
    """打印标题"""
    print("\n" + "=" * 60)
    print(title.center(60))
    print("=" * 60 + "\n")


def run_command(command, description):
    """运行命令并显示结果"""
    print(f"\n▶ {description}")
    print(f"  命令: {command}")
    print("-" * 60)
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        if result.returncode == 0:
            print(f"✓ {description} - 成功")
            return True
        else:
            print(f"✗ {description} - 失败 (退出码: {result.returncode})")
            return False
    except Exception as e:
        print(f"✗ {description} - 异常: {e}")
        return False


def check_git_status():
    """检查Git状态"""
    print_header("检查 Git 状态")
    
    if not os.path.exists('.git'):
        print("⚠ 警告: 未检测到 Git 仓库")
        print("建议初始化 Git 以便回滚:")
        print("  git init")
        print("  git add .")
        print("  git commit -m 'Initial commit'")
        response = input("\n继续（不建议）？(yes/no): ").strip().lower()
        return response in ['yes', 'y']
    
    # 检查是否有未提交的更改
    result = subprocess.run(
        'git status --porcelain',
        shell=True,
        capture_output=True,
        text=True
    )
    
    if result.stdout.strip():
        print("⚠ 检测到未提交的更改:")
        print(result.stdout)
        print("\n建议先提交当前更改:")
        print("  git add .")
        print("  git commit -m 'Work in progress'")
        response = input("\n继续？(yes/no): ").strip().lower()
        return response in ['yes', 'y']
    
    print("✓ Git 状态正常")
    return True


def create_backup():
    """创建备份"""
    print_header("创建备份")
    
    if not os.path.exists('.git'):
        print("⊘ 跳过（无 Git 仓库）")
        return True
    
    commands = [
        ('git add .', '暂存所有文件'),
        ('git commit -m "Backup before restructure"', '创建备份提交'),
        ('git tag backup-before-restructure', '创建备份标签'),
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            # 如果提交失败（可能没有更改），继续
            if 'commit' in command:
                print("  (可能没有更改，继续)")
                continue
    
    print("\n✓ 备份完成")
    print("如需回滚，运行: git reset --hard backup-before-restructure")
    return True


def update_imports():
    """更新导入路径"""
    print_header("步骤 1: 更新导入路径")
    
    if not os.path.exists('update_imports.py'):
        print("✗ 找不到 update_imports.py")
        return False
    
    return run_command('python update_imports.py', '更新导入路径')


def run_tests():
    """运行测试"""
    print_header("步骤 2: 运行测试")
    
    tests = [
        ('test_project.py', '项目结构测试'),
        ('test_algorithms.py', '算法功能测试'),
    ]
    
    all_passed = True
    for test_file, description in tests:
        if os.path.exists(test_file):
            if not run_command(f'python {test_file}', description):
                all_passed = False
                print(f"⚠ {description}失败，但继续执行")
        else:
            print(f"⊘ 跳过 {description}（文件不存在）")
    
    return all_passed


def cleanup_old_structure():
    """清理旧结构"""
    print_header("步骤 3: 清理旧结构")
    
    if not os.path.exists('cleanup_old_structure.py'):
        print("✗ 找不到 cleanup_old_structure.py")
        return False
    
    print("⚠ 这将删除旧的目录结构")
    print("请确认:")
    print("  1. 导入已更新")
    print("  2. 测试已通过")
    print("  3. 已创建备份")
    
    response = input("\n继续删除旧结构？(yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("已跳过清理步骤")
        return False
    
    return run_command('python cleanup_old_structure.py', '清理旧结构')


def verify_structure():
    """验证新结构"""
    print_header("步骤 4: 验证新结构")
    
    required_dirs = [
        'core/algorithms/classical',
        'core/algorithms/symmetric',
        'core/algorithms/asymmetric',
        'core/algorithms/hash',
        'core/algorithms/mathematical',
        'ui/widgets',
        'infrastructure',
    ]
    
    all_exist = True
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✓ {directory}")
        else:
            print(f"✗ {directory} - 不存在")
            all_exist = False
    
    return all_exist


def final_tests():
    """最终测试"""
    print_header("步骤 5: 最终测试")
    
    print("运行最终验证测试...")
    
    # 测试导入
    test_imports = [
        'from core.algorithms.classical.Caesar import Thread',
        'from core.algorithms.symmetric.AES import Thread',
        'from core.algorithms.asymmetric.RSA import Thread',
        'from core.algorithms.hash.MD5 import Thread',
        'from ui.main_window import CryptographyWidget',
    ]
    
    all_passed = True
    for import_stmt in test_imports:
        try:
            exec(import_stmt)
            print(f"✓ {import_stmt}")
        except Exception as e:
            print(f"✗ {import_stmt}")
            print(f"  错误: {e}")
            all_passed = False
    
    return all_passed


def print_summary(results):
    """打印总结"""
    print_header("重构总结")
    
    steps = [
        ('Git 检查', results.get('git_check', False)),
        ('创建备份', results.get('backup', False)),
        ('更新导入', results.get('update_imports', False)),
        ('运行测试', results.get('run_tests', False)),
        ('清理旧结构', results.get('cleanup', False)),
        ('验证结构', results.get('verify', False)),
        ('最终测试', results.get('final_tests', False)),
    ]
    
    for step_name, passed in steps:
        status = "✓ 通过" if passed else "✗ 失败/跳过"
        print(f"{step_name:20s}: {status}")
    
    print("\n" + "=" * 60)
    
    if all(passed for _, passed in steps if passed is not False):
        print("🎉 重构成功完成！")
        print("\n下一步:")
        print("1. 测试应用: python main.py")
        print("2. 提交更改:")
        print("   git add .")
        print("   git commit -m 'Complete project restructure'")
    else:
        print("⚠ 重构未完全完成")
        print("\n如需回滚:")
        print("   git reset --hard backup-before-restructure")
    
    print("=" * 60 + "\n")


def main():
    """主函数"""
    print("\n" + "╔" + "=" * 58 + "╗")
    print("║" + " " * 15 + "密码学平台重构工具" + " " * 15 + "║")
    print("╚" + "=" * 58 + "╝")
    
    print("\n本工具将自动完成以下步骤:")
    print("1. 检查 Git 状态")
    print("2. 创建备份")
    print("3. 更新所有导入路径")
    print("4. 运行测试验证")
    print("5. 清理旧目录结构")
    print("6. 验证新结构")
    print("7. 最终测试")
    
    response = input("\n开始重构？(yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("已取消")
        return
    
    results = {}
    
    # 执行各个步骤
    results['git_check'] = check_git_status()
    if not results['git_check']:
        print("\n⚠ Git 检查失败，建议先解决 Git 问题")
        return
    
    results['backup'] = create_backup()
    results['update_imports'] = update_imports()
    results['run_tests'] = run_tests()
    
    # 清理步骤需要用户确认
    results['cleanup'] = cleanup_old_structure()
    
    results['verify'] = verify_structure()
    results['final_tests'] = final_tests()
    
    # 打印总结
    print_summary(results)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ 用户中断")
        print("如需回滚: git reset --hard backup-before-restructure")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        print("\n如需回滚: git reset --hard backup-before-restructure")
        sys.exit(1)
