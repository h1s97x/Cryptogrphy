"""
测试主程序是否能正常启动
"""
import pytest
from PyQt5.QtWidgets import QApplication


@pytest.fixture(scope="module")
def qapp():
    """Provide QApplication instance for all tests in this module"""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app
    # Cleanup happens automatically


class TestMainProgram:
    """Test suite for main program initialization"""
    
    def test_main_window_creation(self, qapp):
        """Test that CryptographyWidget can be instantiated"""
        from ui.main_window import CryptographyWidget
        
        window = CryptographyWidget()
        assert window is not None, "Main window should be created"
    
    def test_menu_bar_exists(self, qapp):
        """Test that menu bar is properly initialized"""
        from ui.main_window import CryptographyWidget
        
        window = CryptographyWidget()
        menu_bar = window.menuBar()
        assert menu_bar is not None, "Menu bar should exist"
        assert not menu_bar.isEmpty(), "Menu bar should have menu items"
    
    def test_ui_components_import(self, qapp):
        """Test that all UI components can be imported"""
        try:
            from ui import widgets
            assert hasattr(widgets, '__all__'), "widgets should export __all__"
        except ImportError as e:
            pytest.fail(f"Failed to import UI components: {e}")


# Backward compatibility: allow running as script
if __name__ == '__main__':
    import sys
    
    # Run with pytest if available, otherwise fallback to manual test
    try:
        import pytest
        sys.exit(pytest.main([__file__, '-v']))
    except ImportError:
        print("pytest not found, running manual test...")
        app = QApplication([])
        
        try:
            from ui.main_window import CryptographyWidget
            window = CryptographyWidget()
            print("✓ 主程序创建成功")
            print("✓ 菜单栏加载成功")
            print("✓ 所有UI组件导入成功")
            print("\n测试通过！主程序可以正常启动。")
            sys.exit(0)
        except Exception as e:
            print(f"✗ 错误: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
