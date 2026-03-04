# Widgets 目录结构说明

## 为什么有两个 widgets 文件夹？

项目中有两个 widgets 目录，这是为了支持新旧UI共存：

### 1. `ui/widgets/` - 经典UI算法界面

**位置**: `ui/widgets/`

**数量**: 37个算法界面

**状态**: ✅ 完整实现，所有算法可用

**用途**: 
- 经典UI (`python main.py --classic`)
- 传统菜单栏界面
- 所有算法都已实现

**文件列表**:
```
ui/widgets/
├── AES_CBC_MAC_ui.py
├── AES_ui.py
├── Block_Mode_ui.py
├── Caesar_ui.py
├── CRT_ui.py
├── Crypto_1_ui.py
├── DES_ui.py
├── ECC_ui.py
├── ECDSA_ui.py
├── ElGamal_ui.py
├── Enigma_ui.py
├── Euclidean_ui.py
├── Euler_ui.py
├── Frequency_Analysis_ui.py
├── Hash_Reverse_ui.py
├── Hill_ui.py
├── HMAC_MD5_ui.py
├── MD5_ui.py
├── Monoalphabetic_Cipher_ui.py
├── Password_System_ui.py
├── Playfair_ui.py
├── RC4_ui.py
├── RSA_Sign_ui.py
├── RSA_ui.py
├── SEAL_ui.py
├── SHA1_ui.py
├── SHA256_ui.py
├── SHA3_ui.py
├── SIMON_ui.py
├── SM2_Sign_ui.py
├── SM2_ui.py
├── SM3_ui.py
├── SM4_ui.py
├── SPECK_ui.py
├── Vigenere_ui.py
└── ZUC_ui.py
```

### 2. `ui/fluent/widgets/` - Fluent UI算法界面

**位置**: `ui/fluent/widgets/`

**数量**: 8个算法界面（部分迁移）

**状态**: 
- ✅ Hill - 完整实现
- ⏳ 其他 - 占位符，待迁移

**用途**:
- Fluent UI (`python main_fluent.py`)
- 现代化侧边栏界面
- 逐步迁移中

**文件列表**:
```
ui/fluent/widgets/
├── hill_widget.py      ✅ 完整实现
├── caesar_widget.py    ⏳ 占位符
├── vigenere_widget.py  ⏳ 占位符
├── aes_widget.py       ⏳ 占位符
├── des_widget.py       ⏳ 占位符
├── rsa_widget.py       ⏳ 占位符
├── sha256_widget.py    ⏳ 占位符
└── euler_widget.py     ⏳ 占位符
```

## 设计原因

### 为什么不合并？

1. **UI框架不同**
   - 经典UI: 基于 PyQt5 原生组件
   - Fluent UI: 基于 QFluentWidgets 库

2. **代码结构不同**
   - 经典UI: 继承 `CryptographyWidget`
   - Fluent UI: 继承 `ScrollArea`，使用卡片组件

3. **渐进式迁移**
   - 保持经典UI完整可用
   - 逐步迁移到Fluent UI
   - 用户可以选择使用哪个UI

4. **向后兼容**
   - 不破坏现有功能
   - 经典UI作为备选方案

## 迁移计划

### 已完成
- ✅ Hill 密码 - 完整的Fluent UI实现

### 待迁移（优先级）

#### 高优先级（常用算法）
- [ ] Caesar 密码
- [ ] Vigenere 密码
- [ ] AES 加密
- [ ] RSA 加密
- [ ] SHA-256 哈希

#### 中优先级
- [ ] DES 加密
- [ ] MD5 哈希
- [ ] SM4 加密
- [ ] Playfair 密码
- [ ] Enigma 密码

#### 低优先级
- [ ] 其他算法...

### 迁移步骤

1. 参考 `ui/fluent/widgets/hill_widget.py`
2. 复用 `core/algorithms/` 中的算法逻辑
3. 使用 `ui/fluent/components/algorithm_card.py` 中的卡片组件
4. 在 `ui/fluent/main_window.py` 中注册

详见：`docs/guides/QFLUENTWIDGETS_QUICK_START.md`

## 使用建议

### 对于用户

**推荐使用 Fluent UI**:
```bash
python main_fluent.py
```

**如果需要使用未迁移的算法**:
```bash
python main.py --classic
```

### 对于开发者

**迁移新算法时**:
1. 在 `ui/fluent/widgets/` 创建新文件
2. 参考 `hill_widget.py` 的实现
3. 复用 `ui/widgets/` 中的算法逻辑
4. 不要修改 `ui/widgets/` 中的文件（保持经典UI可用）

## 文件对比

### 经典UI vs Fluent UI

| 算法 | 经典UI | Fluent UI | 状态 |
|------|--------|-----------|------|
| Hill | `ui/widgets/Hill_ui.py` | `ui/fluent/widgets/hill_widget.py` | ✅ 已迁移 |
| Caesar | `ui/widgets/Caesar_ui.py` | `ui/fluent/widgets/caesar_widget.py` | ⏳ 待迁移 |
| AES | `ui/widgets/AES_ui.py` | `ui/fluent/widgets/aes_widget.py` | ⏳ 待迁移 |
| RSA | `ui/widgets/RSA_ui.py` | `ui/fluent/widgets/rsa_widget.py` | ⏳ 待迁移 |
| ... | ... | ... | ... |

## 未来计划

### 短期（1-2个月）
- 迁移常用的10-15个算法到Fluent UI
- 保持经典UI可用

### 中期（3-6个月）
- 迁移所有算法到Fluent UI
- 经典UI作为备选

### 长期（6个月+）
- 考虑是否完全移除经典UI
- 或保留经典UI作为"简化模式"

## 常见问题

### Q: 为什么不直接删除 `ui/widgets/`？

A: 因为：
1. 经典UI功能完整，可以作为备选
2. Fluent UI还在迁移中，不是所有算法都可用
3. 保持向后兼容

### Q: 两个文件夹会冲突吗？

A: 不会，因为：
1. 它们在不同的目录下
2. 使用不同的UI框架
3. 通过不同的启动入口调用

### Q: 应该使用哪个？

A: 
- **用户**: 推荐使用 Fluent UI (`python main_fluent.py`)
- **开发**: 参考 Fluent UI 的实现方式

### Q: 如何知道哪些算法已经迁移？

A: 查看 `ui/fluent/widgets/` 目录，或运行 Fluent UI 查看侧边栏

## 总结

- ✅ 两个 widgets 目录是有意设计的
- ✅ 支持新旧UI共存
- ✅ 渐进式迁移策略
- ✅ 保持向后兼容
- ✅ 用户可以选择使用哪个UI

这是一个合理的过渡方案，确保在迁移过程中不影响现有功能。
