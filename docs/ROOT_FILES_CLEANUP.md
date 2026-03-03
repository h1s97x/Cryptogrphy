# 根目录文件清理说明

## 文件分类和建议

### 📦 核心文件（保留在根目录）
- **main.py** - 主程序入口，启动应用
- **menu.py** - 菜单配置文件
- **requirements.txt** - Python 依赖列表
- **readme.md** - 项目说明文档

### 🔧 重构工具脚本（建议移到 scripts/ 目录）
- **cleanup_old_structure.py** - 清理旧目录结构的脚本（重构已完成，可归档）
- **update_imports.py** - 更新导入路径的脚本（重构已完成，可归档）
- **restructure.py** - 一键重构脚本（重构已完成，可归档）

### 🧪 测试文件（建议移到 tests/ 目录）
- **test_project.py** - 项目结构测试
- **test_algorithms.py** - 算法功能测试
- **test.py** - PyQt5 信号测试示例
- **web_test.py** - Web 视图测试示例

### 🛠️ 工具脚本（建议移到 scripts/ 目录）
- **dirtree.py** - 生成目录树的工具
- **dirtree.txt** - 目录树输出文件（可删除，需要时重新生成）

### 📄 文本文件（建议移到 docs/notes/ 目录）
- **任务.txt** - 任务清单（已过时，可归档）
- **软件环境要求.txt** - 环境要求（内容已在 requirements.txt 中，可删除）

### 📦 其他文件
- **pyqt5.7z** - PyQt5 压缩包（37MB，建议删除，可通过 pip 安装）
- **《密码学原理与实践》课程实验实践报告-模板.docx** - 实验报告模板（建议移到 docs/templates/）

## 建议的清理方案

### 方案 A：完全清理（推荐）
```
根目录保留：
├── main.py
├── menu.py
├── requirements.txt
├── readme.md
├── core/
├── ui/
├── infrastructure/
├── resources/
├── CryptographicProtocol/
├── docs/
├── tests/
└── scripts/

移动文件：
- 测试文件 → tests/
- 重构脚本 → scripts/restructure/
- 工具脚本 → scripts/tools/
- 文档模板 → docs/templates/
- 旧任务文件 → docs/archive/

删除文件：
- pyqt5.7z（37MB，可通过 pip 安装）
- dirtree.txt（可重新生成）
- 软件环境要求.txt（内容重复）
```

### 方案 B：保守清理
```
只删除明确不需要的文件：
- pyqt5.7z
- dirtree.txt
- 软件环境要求.txt

其他文件暂时保留，等确认不需要后再清理
```

## 执行建议

1. **先备份**：确保 Git 已提交所有更改
2. **创建目录结构**：scripts/, tests/, docs/templates/, docs/archive/
3. **移动文件**：按照方案 A 移动文件
4. **更新引用**：检查是否有文件引用了这些路径
5. **测试**：运行 `python main.py` 确保应用正常
6. **提交**：`git add . && git commit -m "Clean up root directory"`

## 优先级

### 🔴 高优先级（立即处理）
- 删除 pyqt5.7z（37MB，占用空间大）
- 删除 软件环境要求.txt（内容重复）
- 删除 dirtree.txt（可重新生成）

### 🟡 中优先级（本周处理）
- 移动测试文件到 tests/
- 移动重构脚本到 scripts/restructure/
- 移动文档模板到 docs/templates/

### 🟢 低优先级（有时间再处理）
- 移动工具脚本到 scripts/tools/
- 归档旧任务文件到 docs/archive/
