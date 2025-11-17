"""
测试API接口的脚本
"""
import requests
import sys

def test_api(image_path, api_url='http://localhost:8088/predict'):
    """
    测试API接口
    
    Args:
        image_path: 图片路径
        api_url: API地址
    """
    try:
        with open(image_path, 'rb') as f:
            files = {'image': f}
            response = requests.post(api_url, files=files)
        
        if response.status_code == 200:
            result = response.json()
            print('=' * 50)
            print('预测结果:')
            print(f"  状态: {result.get('status')}")
            print(f"  类型: {result.get('prediction')}")
            print(f"  置信度: {result.get('confidence'):.2%}")
            print(f"  概率分布:")
            for cls, prob in result.get('probabilities', {}).items():
                print(f"    {cls}: {prob:.2%}")
            print('=' * 50)
            return result
        else:
            print(f'错误: HTTP {response.status_code}')
            print(response.json())
            return None
            
    except Exception as e:
        print(f'请求失败: {e}')
        return None

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('用法: python test_api.py <图片路径> [API地址]')
        print('示例: python test_api.py test.jpg http://localhost:8088/predict')
        sys.exit(1)
    
    image_path = sys.argv[1]
    api_url = sys.argv[2] if len(sys.argv) > 2 else 'http://localhost:8088/predict'
    
    test_api(image_path, api_url)

