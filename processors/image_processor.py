# 图片敏感类型分类处理器
# 通过调用 idcard_ocr API 进行图片类型识别

def classify_image(file_path: str) -> str:
    """
    通过调用 idcard_ocr API 进行图片分类识别。
    返回：身份证图片 / 银行卡图片 / 未知类别
    
    Args:
        file_path: 图片文件路径
        
    Returns:
        str: "包含身份证图片" / "包含银行卡图片" / "不包含银行卡和身份证图片"
    """
    try:
        import requests
        import os
        from config import Config
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            import warnings
            warnings.warn(f"图片文件不存在: {file_path}")
            return "不包含银行卡和身份证图片"
        
        # 调用API识别图片类型
        api_url = Config.IDCARD_OCR_API_URL
        timeout = Config.IDCARD_OCR_API_TIMEOUT
        
        try:
            with open(file_path, 'rb') as f:
                files = {'image': f}
                response = requests.post(api_url, files=files, timeout=timeout)
            
            if response.status_code == 200:
                result = response.json()
                
                # 检查API返回状态
                if result.get('status') == 'success':
                    prediction = result.get('prediction', '').lower()
                    
                    # 根据prediction返回对应的类别
                    if prediction == 'idcard':
                        return "包含身份证图片"
                    elif prediction == 'bankcard':
                        return "包含银行卡图片"
                    else:
                        return "不包含银行卡和身份证图片"
                else:
                    import warnings
                    warnings.warn(f"API返回失败状态: {result.get('error', '未知错误')}")
                    return "不包含银行卡和身份证图片"
            else:
                import warnings
                warnings.warn(f"API请求失败: HTTP {response.status_code}")
                return "不包含银行卡和身份证图片"
                
        except requests.exceptions.Timeout:
            import warnings
            warnings.warn(f"OCR API请求超时（{timeout}秒）")
            return "不包含银行卡和身份证图片"
        except requests.exceptions.ConnectionError:
            import warnings
            warnings.warn(f"无法连接到OCR API服务: {api_url}，请确保服务已启动")
            return "不包含银行卡和身份证图片"
        except requests.exceptions.RequestException as e:
            import warnings
            warnings.warn(f"OCR API请求异常: {str(e)}")
            return "不包含银行卡和身份证图片"
            
    except ImportError:
        import warnings
        warnings.warn("requests库未安装，无法调用OCR API，请运行: pip install requests")
        return "不包含银行卡和身份证图片"
    except Exception as e:
        # 捕获所有异常，确保函数不会因为API调用失败而崩溃
        import warnings
        warnings.warn(f"图片分类失败: {str(e)}")
        return "不包含银行卡和身份证图片"
