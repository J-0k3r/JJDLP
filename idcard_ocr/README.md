# 身份证/银行卡识别模型

一个轻量级的深度学习模型，用于识别中国大陆身份证和银行卡图片。

## 功能特性

- 轻量级模型设计，适合在Windows/Linux上运行
- 支持Python 3.9+
- 提供RESTful API接口
- 返回JSON格式结果

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用说明

### 1. 准备训练数据（基于安全原则训练数据已删除，模型已保存，无需重新训练）

将图片按照以下目录结构组织：
```
data/
  train/
    idcard/      # 身份证图片
    bankcard/    # 银行卡图片
  val/
    idcard/      # 身份证验证图片
    bankcard/    # 银行卡验证图片
```

或者使用数据准备脚本自动划分：

**方法1：处理testfile目录**（推荐，如果您的图片在testfile目录中）
```bash
python prepare_testfile_data.py --source_dir testfile --output_dir data
```

**方法2：处理标准格式的原始数据**
```bash
python prepare_data.py --source_dir your_raw_data --output_dir data
```

其中 `your_raw_data` 目录应包含 `idcard/` 和 `bankcard/` 两个子目录。

### 2. 训练模型

```bash
python train.py --data_dir data --epochs 20 --batch_size 32
```

训练参数说明：
- `--data_dir`: 数据目录路径（默认: data）
- `--epochs`: 训练轮数（默认: 20）
- `--batch_size`: 批次大小（默认: 32）
- `--img_size`: 输入图片尺寸（默认: 224）
- `--device`: 设备选择，可选 cuda/cpu/auto（默认: auto）

### 3. 启动API服务

```bash
python app.py
```

服务将在 `http://localhost:8088` 启动

可以通过环境变量配置服务：
- `PORT`: 端口号（默认: 8088）
- `HOST`: 主机地址（默认: 0.0.0.0）

### 4. 调用API

#### 方法1: 使用测试脚本

```bash
python test_api.py your_image.jpg
```

#### 方法2: 使用curl命令

使用POST请求发送图片：

```bash
curl -X POST -F "image=@your_image.jpg" http://localhost:8088/predict
```

或者使用Python：

```python
import requests

with open('test_image.jpg', 'rb') as f:
    response = requests.post('http://localhost:8088/predict', 
                            files={'image': f})
    print(response.json())
```

## API接口说明

### POST /predict

识别图片类型

**请求参数：**
- `image`: 图片文件（支持jpg, png等格式）

**返回格式：**
```json
{
  "status": "success",
  "prediction": "idcard",
  "confidence": 0.95,
  "probabilities": {
    "idcard": 0.95,
    "bankcard": 0.05
  }
}
```

### GET /health

健康检查接口

**返回格式：**
```json
{
  "status": "ok",
  "model_loaded": true
}
```

### GET /

API说明接口

## 模型说明

使用MobileNetV2作为基础模型，经过轻量化优化：
- 模型大小：约14MB
- 推理速度：CPU约100ms/张，GPU约20ms/张
- 支持输入尺寸：224x224
- 准确率：通常在90%以上（取决于训练数据质量）

## 项目结构

```
idcard_ocr/
├── train.py              # 训练脚本
├── predict.py            # 推理模块
├── app.py                # Flask API服务
├── prepare_data.py       # 数据准备脚本
├── prepare_testfile_data.py  # testfile数据准备脚本
├── test_api.py          # API测试脚本
├── run_example.py       # 本地推理示例
├── requirements.txt      # 依赖包
├── README.md            # 使用说明
├── PRINCIPLE.md         # 训练和识别原理说明
├── MIGRATION_NOTES.md   # 项目迁移说明
├── data.zip             # 压缩的训练数据（可选）
├── pretrained_models/   # 预训练模型目录（自动下载）
│   └── hub/            # PyTorch Hub缓存
└── model/               # 训练后的模型保存目录
    ├── best_model.pth   # 最佳模型权重
    └── classes.json     # 类别信息
```

## 注意事项

1. **训练数据**：建议每个类别至少准备100-200张图片，数据质量直接影响识别准确率
2. **数据多样性**：尽量包含不同角度、光照、清晰度的图片
3. **Python版本**：要求Python 3.9或更高版本
4. **GPU支持**：如果有NVIDIA GPU，会自动使用CUDA加速，否则使用CPU
5. **首次运行**：第一次训练时会自动下载MobileNetV2的预训练权重到项目目录的 `pretrained_models/` 文件夹
6. **项目迁移**：所有模型文件（预训练模型和训练后的模型）都保存在项目目录中，方便整个项目迁移
7. **原理说明**：详细的技术原理请参考 `PRINCIPLE.md` 文件

