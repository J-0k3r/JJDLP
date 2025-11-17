"""
快速测试示例
演示如何使用预测器进行本地推理（不需要启动API服务）
"""
from predict import Predictor
import sys
import os

def main():
    if len(sys.argv) < 2:
        print('用法: python run_example.py <图片路径>')
        print('示例: python run_example.py test_image.jpg')
        sys.exit(1)
    
    image_path = sys.argv[1]
    
    if not os.path.exists(image_path):
        print(f'错误: 图片文件 {image_path} 不存在')
        sys.exit(1)
    
    # 检查模型是否存在
    model_path = 'model/best_model.pth'
    if not os.path.exists(model_path):
        print(f'错误: 模型文件 {model_path} 不存在')
        print('请先训练模型: python train.py')
        sys.exit(1)
    
    # 初始化预测器
    print('正在加载模型...')
    predictor = Predictor(model_path=model_path)
    
    # 进行预测
    print(f'正在识别图片: {image_path}')
    result = predictor.predict_file(image_path)
    
    # 显示结果
    print('=' * 50)
    print('预测结果:')
    print(f"  类型: {result['prediction']}")
    print(f"  置信度: {result['confidence']:.2%}")
    print(f"  概率分布:")
    for cls, prob in result['probabilities'].items():
        print(f"    {cls}: {prob:.2%}")
    print('=' * 50)

if __name__ == '__main__':
    main()

