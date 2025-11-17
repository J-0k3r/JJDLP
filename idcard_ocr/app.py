"""
Flask API服务
提供身份证/银行卡识别接口
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from predict import Predictor
from PIL import Image
import io
import os

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 全局预测器
predictor = None

def init_predictor():
    """初始化预测器"""
    global predictor
    model_path = 'model/best_model.pth'
    classes_path = 'model/classes.json'
    
    if not os.path.exists(model_path):
        print(f'警告: 模型文件 {model_path} 不存在')
        print('请先训练模型: python train.py')
        return None
    
    try:
        predictor = Predictor(model_path=model_path, classes_path=classes_path)
        print('预测器初始化成功')
        return predictor
    except Exception as e:
        print(f'预测器初始化失败: {e}')
        return None

@app.route('/predict', methods=['POST'])
def predict():
    """
    识别图片类型
    
    请求:
        POST /predict
        Content-Type: multipart/form-data
        Form data: image (图片文件)
    
    返回:
        JSON格式:
        {
            "status": "success" 或 "error",
            "prediction": "idcard" 或 "bankcard",
            "confidence": 0.95,
            "probabilities": {
                "idcard": 0.95,
                "bankcard": 0.05
            }
        }
    """
    if predictor is None:
        return jsonify({
            'status': 'error',
            'message': '模型未加载，请先训练模型'
        }), 500
    
    # 检查是否上传了文件
    if 'image' not in request.files:
        return jsonify({
            'status': 'error',
            'message': '未提供图片文件，请使用 "image" 作为字段名'
        }), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({
            'status': 'error',
            'message': '未选择文件'
        }), 400
    
    try:
        # 读取图片
        image_bytes = file.read()
        image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        
        # 预测
        result = predictor.predict(image)
        
        # 返回结果
        return jsonify({
            'status': 'success',
            'prediction': result['prediction'],
            'confidence': round(result['confidence'], 4),
            'probabilities': {
                k: round(v, 4) for k, v in result['probabilities'].items()
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'处理图片时出错: {str(e)}'
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """健康检查接口"""
    return jsonify({
        'status': 'ok',
        'model_loaded': predictor is not None
    })

@app.route('/', methods=['GET'])
def index():
    """API说明"""
    return jsonify({
        'name': '身份证/银行卡识别API',
        'version': '1.0',
        'endpoints': {
            'POST /predict': '识别图片类型，需要上传图片文件',
            'GET /health': '健康检查',
            'GET /': 'API说明'
        },
        'usage': {
            'example': 'curl -X POST -F "image=@test.jpg" http://localhost:5000/predict'
        }
    })

if __name__ == '__main__':
    # 初始化预测器
    print('正在初始化模型...')
    init_predictor()
    
    # 启动服务
    port = int(os.environ.get('PORT', 8088))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f'API服务启动在 http://{host}:{port}')
    print(f'接口文档: http://localhost:{port}/')
    
    app.run(host=host, port=port, debug=False)

