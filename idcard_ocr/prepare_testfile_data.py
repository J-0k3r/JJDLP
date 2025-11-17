"""
处理testfile目录中的图片，准备训练数据
自动将testfile/idcard_images和testfile/bankcard_images转换为训练格式
"""
import os
import shutil
from pathlib import Path
import random

def prepare_testfile_data(source_dir='testfile', output_dir='data', train_ratio=0.8):
    """
    从testfile目录准备训练数据
    
    Args:
        source_dir: 源数据目录（包含idcard_images和bankcard_images）
        output_dir: 输出目录
        train_ratio: 训练集比例
    """
    source_path = Path(source_dir)
    output_path = Path(output_dir)
    
    # 检查源目录
    if not source_path.exists():
        print(f'错误: 源目录 {source_dir} 不存在')
        return False
    
    # 创建输出目录结构
    train_idcard = output_path / 'train' / 'idcard'
    train_bankcard = output_path / 'train' / 'bankcard'
    val_idcard = output_path / 'val' / 'idcard'
    val_bankcard = output_path / 'val' / 'bankcard'
    
    for dir_path in [train_idcard, train_bankcard, val_idcard, val_bankcard]:
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # 支持的图片格式
    image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif'}
    
    # 统计信息
    stats = {
        'idcard_train': 0,
        'idcard_val': 0,
        'bankcard_train': 0,
        'bankcard_val': 0
    }
    
    # 处理身份证图片
    idcard_source = source_path / 'idcard_images'
    if idcard_source.exists():
        # 获取所有图片文件（排除.py文件）
        image_files = [
            f for f in idcard_source.iterdir() 
            if f.suffix.lower() in image_extensions and f.is_file()
        ]
        
        if len(image_files) > 0:
            # 随机打乱
            random.shuffle(image_files)
            
            # 划分训练集和验证集
            split_idx = int(len(image_files) * train_ratio)
            train_files = image_files[:split_idx]
            val_files = image_files[split_idx:]
            
            # 复制文件
            for img_file in train_files:
                shutil.copy2(img_file, train_idcard / img_file.name)
                stats['idcard_train'] += 1
            
            for img_file in val_files:
                shutil.copy2(img_file, val_idcard / img_file.name)
                stats['idcard_val'] += 1
            
            print(f'身份证图片:')
            print(f'  训练集: {stats["idcard_train"]} 张')
            print(f'  验证集: {stats["idcard_val"]} 张')
        else:
            print(f'警告: {idcard_source} 中没有找到图片文件')
    else:
        print(f'警告: 目录 {idcard_source} 不存在')
    
    # 处理银行卡图片
    bankcard_source = source_path / 'bankcard_images'
    if bankcard_source.exists():
        # 获取所有图片文件（排除.py文件）
        image_files = [
            f for f in bankcard_source.iterdir() 
            if f.suffix.lower() in image_extensions and f.is_file()
        ]
        
        if len(image_files) > 0:
            # 随机打乱
            random.shuffle(image_files)
            
            # 划分训练集和验证集
            split_idx = int(len(image_files) * train_ratio)
            train_files = image_files[:split_idx]
            val_files = image_files[split_idx:]
            
            # 复制文件
            for img_file in train_files:
                shutil.copy2(img_file, train_bankcard / img_file.name)
                stats['bankcard_train'] += 1
            
            for img_file in val_files:
                shutil.copy2(img_file, val_bankcard / img_file.name)
                stats['bankcard_val'] += 1
            
            print(f'\n银行卡图片:')
            print(f'  训练集: {stats["bankcard_train"]} 张')
            print(f'  验证集: {stats["bankcard_val"]} 张')
        else:
            print(f'警告: {bankcard_source} 中没有找到图片文件')
    else:
        print(f'警告: 目录 {bankcard_source} 不存在')
    
    # 总结
    total_train = stats['idcard_train'] + stats['bankcard_train']
    total_val = stats['idcard_val'] + stats['bankcard_val']
    
    print(f'\n总计:')
    print(f'  训练集: {total_train} 张')
    print(f'  验证集: {total_val} 张')
    print(f'  总计: {total_train + total_val} 张')
    print(f'\n数据准备完成，输出目录: {output_dir}')
    
    return True

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='处理testfile目录中的图片，准备训练数据')
    parser.add_argument('--source_dir', type=str, default='testfile',
                       help='源数据目录（默认: testfile）')
    parser.add_argument('--output_dir', type=str, default='data',
                       help='输出目录（默认: data）')
    parser.add_argument('--train_ratio', type=float, default=0.8,
                       help='训练集比例 (0-1，默认: 0.8)')
    
    args = parser.parse_args()
    
    print('=' * 50)
    print('开始处理testfile目录中的图片...')
    print('=' * 50)
    
    success = prepare_testfile_data(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        train_ratio=args.train_ratio
    )
    
    if success:
        print('\n✅ 数据处理完成！现在可以运行训练:')
        print('   python train.py --data_dir data --epochs 20')
    else:
        print('\n❌ 数据处理失败，请检查错误信息')

