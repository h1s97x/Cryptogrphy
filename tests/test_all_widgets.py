"""
批量测试所有UI组件
自动化测试36个组件的基本功能
"""
import sys
from PyQt5.QtCore import Qt, QCoreApplication
QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)

from PyQt5.QtWidgets import QApplication

# 添加项目根目录到路径
sys.path.insert(0, '.')

# 组件列表
WIDGETS_TO_TEST = {
    '古典密码': [
        ('Caesar', 'ui.widgets.Caesar_ui', 'CaesarWidget'),
        ('Vigenere', 'ui.widgets.Vigenere_ui', 'VigenereWidget'),
        ('Hill', 'ui.widgets.Hill_ui', 'HillWidget'),
        ('Playfair', 'ui.widgets.Playfair_ui', 'PlayfairWidget'),
        ('Enigma', 'ui.widgets.Enigma_ui', 'EnigmaWidget'),
        ('Monoalphabetic', 'ui.widgets.Monoalphabetic_Cipher_ui', 'MonoalphabeticWidget'),
        ('Frequency Analysis', 'ui.widgets.Frequency_Analysis_ui', 'FAWidget'),
    ],
    '对称加密': [
        ('AES', 'ui.widgets.AES_ui', 'AESWidget'),
        ('DES', 'ui.widgets.DES_ui', 'DESWidget'),
        ('SM4', 'ui.widgets.SM4_ui', 'SM4Widget'),
        ('SIMON', 'ui.widgets.SIMON_ui', 'SIMONWidget'),
        ('SPECK', 'ui.widgets.SPECK_ui', 'SPECKWidget'),
        ('Block Mode', 'ui.widgets.Block_Mode_ui', 'BlockModeWidget'),
        ('RC4', 'ui.widgets.RC4_ui', 'RC4Widget'),
        ('ZUC', 'ui.widgets.ZUC_ui', 'ZUCWidget'),
        ('SEAL', 'ui.widgets.SEAL_ui', 'SEALWidget'),
        ('Crypto-1', 'ui.widgets.Crypto_1_ui', 'Crypto1Widget'),
    ],
    '哈希算法': [
        ('MD5', 'ui.widgets.MD5_ui', 'MD5Widget'),
        ('SHA1', 'ui.widgets.SHA1_ui', 'SHA1Widget'),
        ('SHA256', 'ui.widgets.SHA256_ui', 'SHA256Widget'),
        ('SHA3', 'ui.widgets.SHA3_ui', 'SHA3Widget'),
        ('SM3', 'ui.widgets.SM3_ui', 'SM3Widget'),
        ('HMAC-MD5', 'ui.widgets.HMAC_MD5_ui', 'MD5_HMACWidget'),
        ('AES-CBC-MAC', 'ui.widgets.AES_CBC_MAC_ui', 'AES_CBC_MACWidget'),
        ('Hash Reverse', 'ui.widgets.Hash_Reverse_ui', 'HashReverseWidget'),
    ],
    '数学基础': [
        ('Euler', 'ui.widgets.Euler_ui', 'EulerWidget'),
        ('CRT', 'ui.widgets.CRT_ui', 'CRTWidget'),
        ('Euclidean', 'ui.widgets.Euclidean_ui', 'EuclideanWidget'),
    ],
    '其他': [
        ('Password System', 'ui.widgets.Password_System_ui', 'PSWidget'),
    ],
}

class TestResult:
    """测试结果"""
    def __init__(self, name, category):
        self.name = name
        self.category = category
        self.import_success = False
        self.create_success = False
        self.widgets_dict_ok = False
        self.widgets_count = 0
        self.error_message = None
        self.warnings = []

def test_widget(name, module_path, class_name, category):
    """测试单个组件"""
    result = TestResult(name, category)
    
    try:
        # 测试导入
        module = __import__(module_path, fromlist=[class_name])
        widget_class = getattr(module, class_name)
        result.import_success = True
        
        # 测试创建
        widget = widget_class()
        result.create_success = True
        
        # 测试widgets_dict
        if hasattr(widget, 'widgets_dict'):
            result.widgets_dict_ok = True
            result.widgets_count = len(widget.widgets_dict)
            
            # 检查是否为空
            if result.widgets_count == 0:
                result.warnings.append("widgets_dict为空")
        else:
            result.warnings.append("缺少widgets_dict属性")
        
        # 检查窗口标题
        if not widget.windowTitle():
            result.warnings.append("窗口标题为空")
        
        return result
        
    except Exception as e:
        result.error_message = str(e)
        return result

def print_category_results(category, results):
    """打印分类结果"""
    print(f"\n{'='*60}")
    print(f"{category}（{len(results)}个组件）")
    print('='*60)
    
    passed = 0
    failed = 0
    
    for result in results:
        status = "✓" if result.create_success else "✗"
        print(f"{status} {result.name:20s}", end="")
        
        if result.create_success:
            print(f" - {result.widgets_count}个组件", end="")
            passed += 1
            if result.warnings:
                print(f" ⚠️ {', '.join(result.warnings)}", end="")
        else:
            print(f" - 失败: {result.error_message}", end="")
            failed += 1
        
        print()
    
    print(f"\n通过: {passed}/{len(results)}")
    return passed, failed

def generate_report(all_results):
    """生成测试报告"""
    print("\n" + "="*60)
    print("测试报告汇总")
    print("="*60)
    
    total_passed = 0
    total_failed = 0
    
    for category, results in all_results.items():
        passed = sum(1 for r in results if r.create_success)
        failed = sum(1 for r in results if not r.create_success)
        total_passed += passed
        total_failed += failed
        
        status = "✓" if failed == 0 else "✗"
        print(f"{status} {category:15s}: {passed}/{len(results)} 通过")
    
    print("\n" + "="*60)
    print(f"总计: {total_passed}/{total_passed + total_failed} 通过")
    print(f"通过率: {total_passed/(total_passed + total_failed)*100:.1f}%")
    print("="*60)
    
    # 列出失败的组件
    failed_widgets = []
    for category, results in all_results.items():
        for result in results:
            if not result.create_success:
                failed_widgets.append((result.name, result.category, result.error_message))
    
    if failed_widgets:
        print("\n失败的组件：")
        for name, category, error in failed_widgets:
            print(f"  ✗ {name} ({category}): {error}")
    
    # 列出有警告的组件
    warning_widgets = []
    for category, results in all_results.items():
        for result in results:
            if result.warnings:
                warning_widgets.append((result.name, result.category, result.warnings))
    
    if warning_widgets:
        print("\n有警告的组件：")
        for name, category, warnings in warning_widgets:
            print(f"  ⚠️ {name} ({category}): {', '.join(warnings)}")
    
    return total_passed, total_failed

def main():
    """主函数"""
    print("="*60)
    print("批量测试所有UI组件")
    print("="*60)
    print(f"\n总共需要测试 {sum(len(widgets) for widgets in WIDGETS_TO_TEST.values())} 个组件\n")
    
    all_results = {}
    
    for category, widgets in WIDGETS_TO_TEST.items():
        results = []
        for name, module_path, class_name in widgets:
            print(f"测试 {name}...", end=" ")
            result = test_widget(name, module_path, class_name, category)
            results.append(result)
            
            if result.create_success:
                print("✓")
            else:
                print(f"✗ {result.error_message}")
        
        all_results[category] = results
    
    # 打印详细结果
    for category, results in all_results.items():
        print_category_results(category, results)
    
    # 生成报告
    passed, failed = generate_report(all_results)
    
    # 返回状态码
    if failed == 0:
        print("\n🎉 所有测试通过！")
        return 0
    else:
        print(f"\n⚠️ {failed}个组件测试失败")
        return 1

if __name__ == '__main__':
    app = QApplication(sys.argv)
    exit_code = main()
    sys.exit(exit_code)
