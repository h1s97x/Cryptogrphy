"""
测试更新后的Caesar组件
"""
import sys
from PyQt5.QtWidgets import QApplication

# 添加项目根目录到路径
sys.path.insert(0, '.')

from ui.widgets.Caesar_ui import CaesarWidget

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    try:
        window = CaesarWidget()
        print("✓ CaesarWidget created successfully")
        print("✓ render() method executed without errors")
        print("✓ widgets_dict populated:", list(window.widgets_dict.keys()))
        print("\n测试通过！Caesar组件使用新的render()方法工作正常。")
        sys.exit(0)
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
