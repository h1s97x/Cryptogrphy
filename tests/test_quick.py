"""
快速测试脚本 - 验证核心算法功能
"""

def test_caesar():
    """测试Caesar密码"""
    print("测试 Caesar 密码...")
    from core.algorithms.classical.Caesar import Thread
    
    # 测试加密
    plaintext = "HELLO"
    key = 3
    result = []
    def capture_result(text):
        result.append(text)
    
    thread = Thread(None, plaintext, key, 0)
    thread.final_result.connect(capture_result)
    thread.run()
    
    if result and result[0] == "KHOOR":
        print(f"  明文: {plaintext}")
        print(f"  密文: {result[0]}")
        print("✓ Caesar 测试通过")
    else:
        print(f"✗ Caesar 测试失败: 期望 KHOOR, 得到 {result[0] if result else 'None'}")

def test_euler():
    """测试Euler定理"""
    print("测试 Euler 定理...")
    from core.algorithms.mathematical.Euler import EulerFunctionThread
    
    # 测试欧拉函数 φ(10) = 4
    result = []
    def capture_result(text):
        result.append(text)
    
    thread = EulerFunctionThread(None, 10)
    thread.final_result.connect(capture_result)
    thread.run()
    
    if result and result[0] == '4':
        print(f"  φ(10) = {result[0]}")
        print("✓ Euler 测试通过")
    else:
        print(f"✗ Euler 测试失败: 期望 4, 得到 {result[0] if result else 'None'}")

def test_crt():
    """测试中国剩余定理"""
    print("测试 CRT...")
    from core.algorithms.mathematical.CRT import Thread
    
    # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)
    # 解应该是 23
    a_list = [2, 3, 2]
    m_list = [3, 5, 7]
    
    result = []
    def capture_result(text):
        result.append(text)
    
    thread = Thread(None, a_list, m_list)
    thread.print_final_result.connect(capture_result)
    thread.run()
    
    if result and result[0] == '23':
        print(f"  解: x = {result[0]}")
        print("✓ CRT 测试通过")
    else:
        print(f"✗ CRT 测试失败: 期望 23, 得到 {result[0] if result else 'None'}")

if __name__ == "__main__":
    print("=" * 50)
    print("快速算法测试")
    print("=" * 50)
    
    try:
        test_caesar()
        print()
        test_euler()
        print()
        test_crt()
        print()
        print("=" * 50)
        print("测试完成！")
        print("=" * 50)
    except Exception as e:
        print(f"\n✗ 测试出错: {e}")
        import traceback
        traceback.print_exc()
