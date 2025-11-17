"""
数据准备脚本
用于将图片数据按照训练要求组织
"""
import os
import shutil
from pathlib import Path
import argparse

def prepare_data(source_dir, output_dir='data', train_ratio=0.8):
    """
    准备训练数据，将图片分类并划分训练/验证集
    
    Args:
        source_dir: 源数据目录，应该包含 idcard/ 和 bankcard/ 子目录
        output_dir: 输出目录
        train_ratio: 训练集比例
    """
    source_path = Path(source_dir)
    output_path = Path(output_dir)
    
    # 创建输出目录结构
    train_idcard = output_path / 'train' / 'idcard'
    train_bankcard = output_path / 'train' / 'bankcard'
    val_idcard = output_path / 'val' / 'idcard'
    val_bankcard = output_path / 'val' / 'bankcard'
    
    for dir_path in [train_idcard, train_bankcard, val_idcard, val_bankcard]:
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # 支持的图片格式
    image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif'}
    
    # 处理每个类别
    for category in ['idcard', 'bankcard']:
        category_path = source_path / category
        
        if not category_path.exists():
            print(f'警告: 目录 {category_path} 不存在，跳过')
            continue
        
        # 获取所有图片文件
        image_files = [
            f for f in category_path.iterdir() 
            if f.suffix.lower() in image_extensions and f.is_file()
        ]
        
        if len(image_files) == 0:
            print(f'警告: {category_path} 中没有找到图片文件')
            continue
        
        # 随机打乱
        import random
        random.shuffle(image_files)
        
        # 划分训练集和验证集
        split_idx = int(len(image_files) * train_ratio)
        train_files = image_files[:split_idx]
        val_files = image_files[split_idx:]
        
        # 复制文件
        train_target = train_idcard if category == 'idcard' else train_bankcard
        val_target = val_idcard if category == 'idcard' else val_bankcard
        
        for img_file in train_files:
            shutil.copy2(img_file, train_target / img_file.name)
        
        for img_file in val_files:
            shutil.copy2(img_file, val_target / img_file.name)
        
        print(f'{category}:')
        print(f'  训练集: {len(train_files)} 张')
        print(f'  验证集: {len(val_files)} 张')
    
    print(f'\n数据准备完成，输出目录: {output_dir}')

def main():
    parser = argparse.ArgumentParser(description='准备训练数据')
    parser.add_argument('--source_dir', type=str, required=True,
                       help='源数据目录，应包含 idcard/ 和 bankcard/ 子目录')
    parser.add_argument('--output_dir', type=str, default='data',
                       help='输出目录')
    parser.add_argument('--train_ratio', type=float, default=0.8,
                       help='训练集比例 (0-1)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.source_dir):
        print(f'错误: 源目录 {args.source_dir} 不存在')
        return
    
    prepare_data(args.source_dir, args.output_dir, args.train_ratio)

if __name__ == '__main__':
    main()

