"""
批量为算法Widget添加介绍按钮的辅助脚本
"""

from pathlib import Path

# 算法名称映射
ALGORITHM_MAP = {
    'aes': 'AES',
    'caesar': 'Caesar',
    'des': 'DES',
    'hill': 'Hill',
    'md5': 'MD5',
    'sm4': 'SM4',
    'vigenere': 'Vigenere'
}

# Widget文件映射
WIDGET_FILES = {
    'AES': 'ui/widgets/aes_widget.py',
    'Caesar': 'ui/widgets/caesar_widget.py',
    'DES': 'ui/widgets/des_widget.py',
    'Hill': 'ui/widgets/hill_widget.py',
    'MD5': 'ui/widgets/md5_widget.py',
    'SM4': 'ui/widgets/sm4_widget.py',
    'Vigenere': 'ui/widgets/vigenere_widget.py'
}


def check_html_pages():
    """检查哪些算法有HTML介绍页面"""
    html_dir = Path('resources/html')
    available = []
    
    for algo_dir in html_dir.iterdir():
        if algo_dir.is_dir():
            index_file = algo_dir / 'index.html'
            if index_file.exists():
                algo_name = ALGORITHM_MAP.get(algo_dir.name)
                if algo_name:
                    available.append(algo_name)
                    print(f"✅ {algo_name}: {index_file}")
    
    return available


def check_widget_files():
    """检查哪些Widget文件存在"""
    existing = []
    missing = []
    
    for algo_name, widget_path in WIDGET_FILES.items():
        path = Path(widget_path)
        if path.exists():
            existing.append((algo_name, widget_path))
            print(f"✅ {algo_name} Widget: {widget_path}")
        else:
            missing.append((algo_name, widget_path))
            print(f"❌ {algo_name} Widget: {widget_path} (不存在)")
    
    return existing, missing


def generate_integration_code(algo_name):
    """生成集成代码示例"""
    code = f"""
# 在 {WIDGET_FILES.get(algo_name, 'widget文件')} 中添加：

# 1. 导入语句（在文件顶部）
from ui.components.intro_button import AlgorithmIntroButton

# 2. 在 initUI() 方法中，标题和描述之间添加：
# 描述和介绍按钮
descLayout = QHBoxLayout()
desc = BodyLabel("算法描述...")
desc.setWordWrap(True)
descLayout.addWidget(desc, 1)

# 算法介绍按钮
self.introBtn = AlgorithmIntroButton("{algo_name}")
descLayout.addWidget(self.introBtn)

layout.addLayout(descLayout)
"""
    return code


def main():
    print("=" * 60)
    print("HTML 算法介绍页面集成检查")
    print("=" * 60)
    
    print("\n1. 检查可用的HTML介绍页面：")
    print("-" * 60)
    available_html = check_html_pages()
    
    print("\n2. 检查Widget文件：")
    print("-" * 60)
    existing_widgets, missing_widgets = check_widget_files()
    
    print("\n3. 集成建议：")
    print("-" * 60)
    
    # 找出既有HTML又有Widget的算法
    can_integrate = []
    for algo_name in available_html:
        if algo_name in [w[0] for w in existing_widgets]:
            can_integrate.append(algo_name)
    
    if can_integrate:
        print(f"\n可以立即集成的算法（{len(can_integrate)}个）：")
        for algo_name in can_integrate:
            print(f"  • {algo_name}")
        
        print("\n集成代码示例（以AES为例）：")
        print(generate_integration_code("AES"))
    
    if missing_widgets:
        print(f"\n缺少Widget文件的算法（{len(missing_widgets)}个）：")
        for algo_name, widget_path in missing_widgets:
            print(f"  • {algo_name}: {widget_path}")
    
    print("\n4. 下一步行动：")
    print("-" * 60)
    print("  1. 为现有Widget添加介绍按钮（参考 docs/HTML_INTEGRATION.md）")
    print("  2. 为没有HTML页面的算法创建介绍页面")
    print("  3. 测试所有集成的介绍按钮")
    print("=" * 60)


if __name__ == '__main__':
    main()
