# 测试目录

本目录包含项目的所有测试文件。

## 测试结构

### 算法测试

- `test_algorithms.py` - 算法功能测试

### 协议测试

`protocols/` 目录包含密码协议的测试脚本：
- `test_replay_attack.py` - 重放攻击协议测试
- `test_verify.py` - 挑战-响应验证协议测试
- `test_millionaire.py` - 百万富翁问题协议测试
- `test_zkp.py` - 零知识证明协议测试
- `test_digital_envelope.py` - 数字信封协议测试
- `test_diffie_hellman.py` - DH密钥交换协议测试
- `test_digital_certificate.py` - 数字证书协议测试

## 运行测试

### 运行单个测试

```bash
# 算法测试
python tests/test_algorithms.py

# 协议测试
python tests/protocols/test_replay_attack.py
python tests/protocols/test_verify.py
python tests/protocols/test_millionaire.py
python tests/protocols/test_zkp.py
python tests/protocols/test_digital_envelope.py
python tests/protocols/test_diffie_hellman.py
python tests/protocols/test_digital_certificate.py
```

### 运行所有测试

```bash
# 运行所有协议测试
cd tests/protocols
for file in test_*.py; do python "$file"; done
```

## 测试说明

- 协议测试会打开GUI窗口，需要手动关闭
- 测试主要用于验证功能完整性和UI正确性
- 不是自动化单元测试，而是交互式功能测试
