"""
测试CryptographyWidget的render()方法
"""
import sys
from PyQt5.QtWidgets import QApplication

# 添加项目根目录到路径
sys.path.insert(0, '.')

from ui.main_window import CryptographyWidget, Group, PlainTextEdit, Button, KeyGroup, Key

class TestRenderWidget(CryptographyWidget):
    """测试render()方法的简单组件"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Test Render Method")
        
        # 配置UI组件
        self.groups_config = [
            KeyGroup(
                name="Key Configuration",
                key_edit=[
                    Key(id="TestKey", label="Test Key", default_text="123", enabled=True)
                ],
                combo_box=[],
                buttons=[]
            ),
            Group(
                name="Test Group",
                plain_text_edits=[
                    PlainTextEdit(id="Input", label="Input Text", default_text="Hello World"),
                    PlainTextEdit(id="Output", label="Output Text", default_text="", read_only=True)
                ],
                buttons=[
                    Button(id="TestButton", name="Test Button", clicked_function=self.test_action)
                ]
            )
        ]
        
        # 调用render方法
        self.render()
        self.log_message("Test widget initialized successfully.")
    
    def test_action(self):
        """测试按钮点击"""
        input_text = self.widgets_dict["Input"].get_text()
        self.widgets_dict["Output"].set_text(f"Processed: {input_text}")
        self.log_message(f"Test action executed with input: {input_text}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = TestRenderWidget()
    print("✓ Test widget created successfully")
    print("✓ render() method executed without errors")
    print("✓ widgets_dict populated:", list(window.widgets_dict.keys()))
    print("\n测试通过！render()方法工作正常。")
    sys.exit(0)
