# 项目迁移说明

## 模型文件位置

本项目已配置为将所有模型文件保存在项目目录中，方便迁移：

### 预训练模型
- **位置**: `pretrained_models/` 目录
- **说明**: MobileNetV2 预训练权重会自动下载到此目录
- **大小**: 约 14MB
- **自动管理**: 首次训练时自动下载，后续训练会复用

### 训练后的模型
- **位置**: `model/` 目录
- **文件**:
  - `best_model.pth`: 训练后的最佳模型权重
  - `classes.json`: 类别信息（idcard, bankcard）

## 迁移步骤

### 完整迁移（包含预训练模型）
如果需要完整迁移项目，请确保包含以下目录：
```
idcard_ocr/
├── pretrained_models/   # 预训练模型（约14MB）
│   └── hub/
└── model/                # 训练后的模型
    ├── best_model.pth
    └── classes.json
```

### 仅迁移训练后的模型（推荐）
如果目标环境可以访问网络下载预训练模型，只需迁移：
```
idcard_ocr/
└── model/                # 训练后的模型
    ├── best_model.pth
    └── classes.json
```

首次运行时，预训练模型会自动下载到 `pretrained_models/` 目录。

## 技术实现

- 使用 `TORCH_HOME` 环境变量将 PyTorch 模型缓存目录设置为项目目录
- 使用新的 `weights` API 替代已弃用的 `pretrained` 参数
- 所有模型相关文件都在项目目录中，不依赖系统缓存

## 验证

运行以下命令验证模型文件位置：
```bash
# 检查预训练模型
ls pretrained_models/hub/checkpoints/

# 检查训练后的模型
ls model/
```

