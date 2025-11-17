"""
训练身份证/银行卡识别模型
使用MobileNetV2作为轻量级基础模型
"""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from torchvision import datasets, transforms, models
from torchvision.models import MobileNet_V2_Weights
import argparse
import os
from pathlib import Path

# 设置模型缓存目录到项目目录
def setup_model_cache():
    """设置预训练模型缓存目录到项目目录"""
    project_dir = Path(__file__).parent.absolute()
    cache_dir = project_dir / 'pretrained_models'
    cache_dir.mkdir(exist_ok=True)
    
    # 设置环境变量，让torch下载模型到项目目录
    os.environ['TORCH_HOME'] = str(cache_dir)
    
    return cache_dir

class IDCardClassifier(nn.Module):
    """轻量级身份证/银行卡分类器"""
    def __init__(self, num_classes=2):
        super(IDCardClassifier, self).__init__()
        # 使用预训练的MobileNetV2作为特征提取器（使用新的weights API）
        self.backbone = models.mobilenet_v2(weights=MobileNet_V2_Weights.IMAGENET1K_V1)
        # 修改分类层
        self.backbone.classifier = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(self.backbone.last_channel, num_classes)
        )
    
    def forward(self, x):
        return self.backbone(x)

def get_data_loaders(data_dir, batch_size=32, img_size=224):
    """创建数据加载器"""
    # 数据增强和预处理
    train_transform = transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.RandomHorizontalFlip(p=0.5),
        transforms.RandomRotation(degrees=5),
        transforms.ColorJitter(brightness=0.2, contrast=0.2),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], 
                           std=[0.229, 0.224, 0.225])
    ])
    
    val_transform = transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], 
                           std=[0.229, 0.224, 0.225])
    ])
    
    # 加载数据集
    train_dataset = datasets.ImageFolder(
        root=os.path.join(data_dir, 'train'),
        transform=train_transform
    )
    
    val_dataset = datasets.ImageFolder(
        root=os.path.join(data_dir, 'val'),
        transform=val_transform
    )
    
    train_loader = DataLoader(
        train_dataset, 
        batch_size=batch_size, 
        shuffle=True,
        num_workers=2
    )
    
    val_loader = DataLoader(
        val_dataset, 
        batch_size=batch_size, 
        shuffle=False,
        num_workers=2
    )
    
    return train_loader, val_loader, train_dataset.classes

def train_model(model, train_loader, val_loader, epochs=20, device='cuda'):
    """训练模型"""
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=7, gamma=0.1)
    
    best_val_acc = 0.0
    
    for epoch in range(epochs):
        # 训练阶段
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for images, labels in train_loader:
            images, labels = images.to(device), labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            train_total += labels.size(0)
            train_correct += (predicted == labels).sum().item()
        
        # 验证阶段
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for images, labels in val_loader:
                images, labels = images.to(device), labels.to(device)
                outputs = model(images)
                loss = criterion(outputs, labels)
                
                val_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                val_total += labels.size(0)
                val_correct += (predicted == labels).sum().item()
        
        train_acc = 100 * train_correct / train_total
        val_acc = 100 * val_correct / val_total
        
        print(f'Epoch [{epoch+1}/{epochs}]')
        print(f'Train Loss: {train_loss/len(train_loader):.4f}, '
              f'Train Acc: {train_acc:.2f}%')
        print(f'Val Loss: {val_loss/len(val_loader):.4f}, '
              f'Val Acc: {val_acc:.2f}%')
        print('-' * 50)
        
        scheduler.step()
        
        # 保存最佳模型
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), 'model/best_model.pth')
            print(f'保存最佳模型，验证准确率: {val_acc:.2f}%')
    
    return model

def main():
    parser = argparse.ArgumentParser(description='训练身份证/银行卡识别模型')
    parser.add_argument('--data_dir', type=str, default='data',
                       help='数据目录路径')
    parser.add_argument('--epochs', type=int, default=20,
                       help='训练轮数')
    parser.add_argument('--batch_size', type=int, default=32,
                       help='批次大小')
    parser.add_argument('--img_size', type=int, default=224,
                       help='输入图片尺寸')
    parser.add_argument('--device', type=str, default='auto',
                       help='设备 (cuda/cpu/auto)')
    
    args = parser.parse_args()
    
    # 设置模型缓存目录到项目目录
    cache_dir = setup_model_cache()
    print(f'预训练模型将下载到: {cache_dir}')
    
    # 设置设备
    if args.device == 'auto':
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    else:
        device = torch.device(args.device)
    
    print(f'使用设备: {device}')
    
    # 创建模型目录
    os.makedirs('model', exist_ok=True)
    
    # 检查并解压数据（如果存在data.zip但data目录不存在）
    if not os.path.exists(args.data_dir) and os.path.exists('data.zip'):
        print('检测到 data.zip 文件，正在解压...')
        import zipfile
        try:
            with zipfile.ZipFile('data.zip', 'r') as zip_ref:
                zip_ref.extractall('.')
            print(f'数据解压完成: {args.data_dir}')
        except Exception as e:
            print(f'解压失败: {e}')
            print('请手动解压 data.zip 文件')
            return
    
    # 检查数据目录
    if not os.path.exists(args.data_dir):
        print(f'错误: 数据目录 {args.data_dir} 不存在')
        if not os.path.exists('data.zip'):
            print('请按照以下结构组织数据:')
            print('data/')
            print('  train/')
            print('    idcard/')
            print('    bankcard/')
            print('  val/')
            print('    idcard/')
            print('    bankcard/')
            print('\n或者使用 pack_data.py 打包数据为 data.zip')
        else:
            print('检测到 data.zip 存在，但解压失败')
            print('请手动解压 data.zip 文件')
        return
    
    # 加载数据
    print('加载数据...')
    train_loader, val_loader, classes = get_data_loaders(
        args.data_dir, 
        batch_size=args.batch_size,
        img_size=args.img_size
    )
    
    print(f'类别: {classes}')
    print(f'训练样本数: {len(train_loader.dataset)}')
    print(f'验证样本数: {len(val_loader.dataset)}')
    
    # 创建模型
    model = IDCardClassifier(num_classes=len(classes))
    model = model.to(device)
    
    # 保存类别信息
    import json
    with open('model/classes.json', 'w', encoding='utf-8') as f:
        json.dump(classes, f, ensure_ascii=False, indent=2)
    
    # 训练模型
    print('开始训练...')
    train_model(model, train_loader, val_loader, 
                epochs=args.epochs, device=device)
    
    print('训练完成!')
    print(f'最佳模型保存在: model/best_model.pth')

if __name__ == '__main__':
    main()

