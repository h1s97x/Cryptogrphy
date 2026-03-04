"""
快速测试更新后的组件
"""
import sys

# 必须在创建QApplication之前导入
from PyQt5.QtCore import Qt, QCoreApplication
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)

from PyQt5.QtWidgets import QApplication

# 添加项目根目录到路径
sys.path.insert(0, '.')

def test_imports():
    """测试所有组件能否正常导入"""
    print("测试组件导入...")
    try:
        from ui.main_window import CryptographyWidget
        print("✓ CryptographyWidget导入成功")
        
        from ui import widgets
        print(f"✓ UI组件导入成功，共{len(widgets.__all__)}个组件")
        
        return True
    except Exception as e:
        print(f"✗ 导入失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_main_window():
    """测试主窗口创建"""
    print("\n测试主窗口创建...")
    try:
        from ui.main_window import CryptographyWidget
        window = CryptographyWidget()
        print("✓ 主窗口创建成功")
        print(f"✓ 窗口标题: {window.windowTitle()}")
        return True
    except Exception as e:
        print(f"✗ 创建失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_caesar_widget():
    """测试Caesar组件"""
    print("\n测试Caesar组件...")
    try:
        from ui.widgets.Caesar_ui import CaesarWidget
        widget = CaesarWidget()
        print("✓ Caesar组件创建成功")
        print(f"✓ widgets_dict包含{len(widget.widgets_dict)}个组件")
        return True
    except Exception as e:
        print(f"✗ 创建失败: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    print("=" * 60)
    print("快速测试 - 批量更新后的组件")
    print("=" * 60)
    
    results = []
    results.append(("导入测试", test_imports()))
    results.append(("主窗口测试", test_main_window()))
    results.append(("Caesar组件测试", test_caesar_widget()))
    
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"{name}: {status}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    print(f"\n总计: {passed}/{total} 通过")
    
    if passed == total:
        print("\n🎉 所有测试通过！")
        sys.exit(0)
    else:
        print("\n⚠️ 部分测试失败")
        sys.exit(1)
