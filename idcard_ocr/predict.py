"""
模型推理模块
用于加载模型并进行预测
"""
import torch
import torch.nn as nn
from torchvision import transforms, models
from PIL import Image
import json
import os

class IDCardClassifier(nn.Module):
    """轻量级身份证/银行卡分类器"""
    def __init__(self, num_classes=2):
        super(IDCardClassifier, self).__init__()
        self.backbone = models.mobilenet_v2(pretrained=False)
        self.backbone.classifier = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(self.backbone.last_channel, num_classes)
        )
    
    def forward(self, x):
        return self.backbone(x)

class Predictor:
    """预测器类"""
    def __init__(self, model_path='model/best_model.pth', 
                 classes_path='model/classes.json', 
                 device='auto'):
        """
        初始化预测器
        
        Args:
            model_path: 模型文件路径
            classes_path: 类别文件路径
            device: 设备 (cuda/cpu/auto)
        """
        # 设置设备
        if device == 'auto':
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(device)
        
        # 加载类别
        if os.path.exists(classes_path):
            with open(classes_path, 'r', encoding='utf-8') as f:
                self.classes = json.load(f)
        else:
            self.classes = ['idcard', 'bankcard']
        
        # 加载模型
        self.model = IDCardClassifier(num_classes=len(self.classes))
        
        if os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            print(f'模型加载成功: {model_path}')
        else:
            print(f'警告: 模型文件 {model_path} 不存在，使用未训练的模型')
        
        self.model = self.model.to(self.device)
        self.model.eval()
        
        # 图像预处理
        self.transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], 
                               std=[0.229, 0.224, 0.225])
        ])
    
    def predict(self, image):
        """
        预测图片类型
        
        Args:
            image: PIL Image 或图片路径
            
        Returns:
            dict: {
                'prediction': 'idcard' 或 'bankcard',
                'confidence': 0.0-1.0,
                'probabilities': {类别: 概率}
            }
        """
        # 加载图片
        if isinstance(image, str):
            image = Image.open(image).convert('RGB')
        elif not isinstance(image, Image.Image):
            # 如果是numpy数组或其他格式，转换为PIL Image
            image = Image.fromarray(image).convert('RGB')
        
        # 预处理
        image_tensor = self.transform(image).unsqueeze(0).to(self.device)
        
        # 预测
        with torch.no_grad():
            outputs = self.model(image_tensor)
            probabilities = torch.softmax(outputs, dim=1)
            confidence, predicted = torch.max(probabilities, 1)
            
        # 获取结果
        pred_idx = predicted.item()
        pred_class = self.classes[pred_idx]
        conf = confidence.item()
        
        # 构建概率字典
        prob_dict = {}
        for i, class_name in enumerate(self.classes):
            prob_dict[class_name] = probabilities[0][i].item()
        
        return {
            'prediction': pred_class,
            'confidence': conf,
            'probabilities': prob_dict
        }
    
    def predict_file(self, image_path):
        """
        从文件路径预测
        
        Args:
            image_path: 图片文件路径
            
        Returns:
            dict: 预测结果
        """
        return self.predict(image_path)

