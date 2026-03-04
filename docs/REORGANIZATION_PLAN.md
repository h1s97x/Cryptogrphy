# 文档重组方案

## 当前问题

1. **文档过多**：根目录有15个MD文件
2. **分类混乱**：阶段报告、计划、完成报告混在一起
3. **重复内容**：多个文档记录相似的内容
4. **难以查找**：用户不知道该看哪个文档

## 重组方案

### 新的文档结构

```
docs/
├── README.md                          # 文档导航（新建）
├── ARCHITECTURE.md                    # 系统架构（保留）
├── ROADMAP.md                         # 技术路线图（保留）
├── CHANGELOG.md                       # 变更日志（新建，合并所有完成报告）
│
├── guides/                            # 用户指南
│   ├── QUICK_START.md                # 快速开始（保留）
│   ├── UI_COMPONENT_GUIDE.md         # UI组件开发指南（合并迁移指南）
│   └── DEVELOPMENT_GUIDE.md          # 开发指南（新建）
│
├── phases/                            # 阶段文档（新建目录）
│   ├── phase1/                       # 阶段1文档
│   │   ├── PLAN.md                   # 执行计划
│   │   ├── PROGRESS.md               # 进度报告
│   │   └── COMPLETE.md               # 完成报告
│   └── phase2/                       # 阶段2文档
│       ├── PLAN.md
│       └── COMPLETE.md
│
├── archive/                           # 归档文档
│   ├── old_reports/                  # 旧报告
│   │   ├── CLEANUP_COMPLETE.md
│   │   ├── DOCUMENT_ANALYSIS.md
│   │   ├── DOCUMENTATION_COMPLETE.md
│   │   ├── BATCH_UPDATE_COMPLETE.md
│   │   └── UI_OPTIMIZATION_PLAN.md
│   └── restructure/                  # 重构文档
│       └── 密码学平台重构需求规格说明书.md
│
├── notes/                             # 开发笔记（保留）
│   ├── Python.md
│   ├── Python导入库.md
│   └── 延迟导入.md
│
└── reports/                           # 实验报告（保留）
    └── 实验报告.md
```

---

## 执行步骤

### 第1步：创建新文档

1. **docs/README.md** - 文档导航
2. **docs/CHANGELOG.md** - 变更日志
3. **docs/guides/DEVELOPMENT_GUIDE.md** - 开发指南

### 第2步：移动阶段文档

```bash
# 创建phases目录
mkdir -p docs/phases/phase1 docs/phases/phase2

# 移动阶段1文档
mv docs/PHASE1_PLAN.md docs/phases/phase1/PLAN.md
mv docs/PHASE1_PROGRESS.md docs/phases/phase1/PROGRESS.md
mv docs/PHASE1_COMPLETE.md docs/phases/phase1/COMPLETE.md

# 移动阶段2文档
mv docs/PHASE2_PLAN.md docs/phases/phase2/PLAN.md
mv docs/PHASE2_COMPLETE.md docs/phases/phase2/COMPLETE.md
```

### 第3步：归档旧文档

```bash
# 创建归档目录
mkdir -p docs/archive/old_reports

# 移动旧报告
mv docs/CLEANUP_COMPLETE.md docs/archive/old_reports/
mv docs/DOCUMENT_ANALYSIS.md docs/archive/old_reports/
mv docs/DOCUMENTATION_COMPLETE.md docs/archive/old_reports/
mv docs/BATCH_UPDATE_COMPLETE.md docs/archive/old_reports/
mv docs/UI_OPTIMIZATION_PLAN.md docs/archive/old_reports/
mv docs/UI_RENDER_OPTIMIZATION.md docs/archive/old_reports/
mv docs/NEXT_STEPS.md docs/archive/old_reports/
```

### 第4步：合并和重命名

```bash
# 合并UI组件指南
mv docs/guides/UI_COMPONENT_MIGRATION_GUIDE.md docs/guides/UI_COMPONENT_GUIDE.md

# 删除空目录
rmdir docs/templates
```

### 第5步：更新FINAL_STATUS.md

将FINAL_STATUS.md作为项目当前状态的快照，移到根目录或保留在docs/

---

## 最终结构

### 核心文档（6个）

1. **README.md** - 项目说明（根目录）
2. **docs/README.md** - 文档导航
3. **docs/ARCHITECTURE.md** - 系统架构
4. **docs/ROADMAP.md** - 技术路线图
5. **docs/CHANGELOG.md** - 变更日志
6. **docs/FINAL_STATUS.md** - 当前状态

### 用户指南（3个）

1. **docs/guides/QUICK_START.md** - 快速开始
2. **docs/guides/UI_COMPONENT_GUIDE.md** - UI组件开发
3. **docs/guides/DEVELOPMENT_GUIDE.md** - 开发指南

### 阶段文档（5个）

- **docs/phases/phase1/** - 阶段1文档（3个）
- **docs/phases/phase2/** - 阶段2文档（2个）

### 其他（归档、笔记、报告）

- **docs/archive/** - 归档文档（7个）
- **docs/notes/** - 开发笔记（3个）
- **docs/reports/** - 实验报告（1个）

---

## 文档数量对比

| 类别 | 重组前 | 重组后 | 减少 |
|------|--------|--------|------|
| 根目录文档 | 15个 | 6个 | -60% |
| 总文档数 | 24个 | 20个 | -17% |
| 核心文档 | 混乱 | 清晰 | ✅ |

---

## 优点

1. **清晰的导航**：README.md提供文档地图
2. **分类明确**：核心、指南、阶段、归档
3. **易于查找**：用户知道该看哪个文档
4. **减少混乱**：根目录只有6个核心文档
5. **保留历史**：旧文档归档而不是删除

---

## 执行？

是否执行此重组方案？

**选项A**：立即执行（推荐）
- 清理文档结构
- 提升可读性
- 便于维护

**选项B**：稍后执行
- 继续当前工作
- 后续再整理

**选项C**：修改方案
- 你有更好的想法？
- 我可以调整方案
