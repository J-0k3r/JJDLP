#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLP系统测试脚本
"""

import sys
import os

def test_imports():
    """测试导入"""
    print("测试模块导入...")
    
    try:
        from config import Config, SensitivityLevel, ActionType
        print("✓ 配置模块导入成功")
    except ImportError as e:
        print(f"✗ 配置模块导入失败: {e}")
        return False
    
    try:
        from core.detector import SensitiveDataDetector, DataMasker, RiskAssessment
        print("✓ 检测器模块导入成功")
    except ImportError as e:
        print(f"✗ 检测器模块导入失败: {e}")
        return False
    
    try:
        from processors.file_processor import FileProcessorFactory
        print("✓ 文件处理器模块导入成功")
    except ImportError as e:
        print(f"✗ 文件处理器模块导入失败: {e}")
        return False
    
    return True

def test_detector():
    """测试敏感信息检测"""
    print("\n测试敏感信息检测...")
    
    try:
        from core.detector import SensitiveDataDetector
        
        detector = SensitiveDataDetector()
        
        # 测试文本
        test_text = """
        姓名：张三
        身份证号：110101199001011234
        手机号：13812345678
        银行卡号：6222021234567890123
        邮箱：zhangsan@example.com
        地址：北京市朝阳区建国路88号
        """
        
        sensitive_items = detector.detect_sensitive_data(test_text)
        
        print(f"检测到 {len(sensitive_items)} 个敏感信息:")
        for item in sensitive_items:
            print(f"  - {item.type}: {item.content} (置信度: {item.confidence:.2f})")
        
        return True
        
    except Exception as e:
        print(f"✗ 检测器测试失败: {e}")
        return False

def test_masking():
    """测试数据脱敏"""
    print("\n测试数据脱敏...")
    
    try:
        from core.detector import SensitiveDataDetector, DataMasker
        
        detector = SensitiveDataDetector()
        masker = DataMasker()
        
        test_text = "我的身份证号是110101199001011234，手机号是13812345678"
        
        sensitive_items = detector.detect_sensitive_data(test_text)
        masked_text = masker.mask_sensitive_data(test_text, sensitive_items)
        
        print(f"原始文本: {test_text}")
        print(f"脱敏后: {masked_text}")
        
        return True
        
    except Exception as e:
        print(f"✗ 脱敏测试失败: {e}")
        return False

def test_file_processor():
    """测试文件处理器"""
    print("\n测试文件处理器...")
    
    try:
        from processors.file_processor import FileProcessorFactory
        
        factory = FileProcessorFactory()
        
        # 测试不同文件类型
        test_files = [
            "test.txt",
            "test.pdf", 
            "test.docx",
            "test.json",
            "test.csv",
            "test.jpg"
        ]
        
        for file_path in test_files:
            processor = factory.get_processor(file_path)
            if processor:
                print(f"✓ {file_path} - 支持")
            else:
                print(f"✗ {file_path} - 不支持")
        
        return True
        
    except Exception as e:
        print(f"✗ 文件处理器测试失败: {e}")
        return False

def main():
    """主函数"""
    print("=" * 50)
    print("DLP系统功能测试")
    print("=" * 50)
    
    tests = [
        ("模块导入", test_imports),
        ("敏感信息检测", test_detector),
        ("数据脱敏", test_masking),
        ("文件处理器", test_file_processor),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}测试:")
        if test_func():
            print(f"✓ {test_name}测试通过")
            passed += 1
        else:
            print(f"✗ {test_name}测试失败")
    
    print("\n" + "=" * 50)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("✓ 所有测试通过，系统可以正常使用")
        return 0
    else:
        print("✗ 部分测试失败，请检查系统配置")
        return 1

if __name__ == "__main__":
    sys.exit(main())
