#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
调试脱敏问题
"""

from core.detector import SensitiveDataDetector, DataMasker

def debug_masking():
    """调试脱敏问题"""
    print("=== 调试脱敏问题 ===")
    
    detector = SensitiveDataDetector()
    masker = DataMasker()
    
    test_text = "我的身份证号是110101199001011234，手机号是13812345678，银行卡号是6222021234567890123"
    print(f"测试文本: {test_text}")
    
    # 检测敏感信息
    sensitive_items = detector.detect_sensitive_data(test_text)
    print(f"\n检测到 {len(sensitive_items)} 个敏感信息:")
    for item in sensitive_items:
        print(f"  - {item.type}: {item.content} (置信度: {item.confidence:.2f}, 位置: {item.position})")
    
    # 检查脱敏前的验证
    print(f"\n脱敏前验证:")
    for item in sensitive_items:
        is_valid = masker._is_valid_sensitive_content(item)
        print(f"  - {item.type}: {item.content} -> 有效: {is_valid}")
    
    # 执行脱敏
    masked_text = masker.mask_sensitive_data(test_text, sensitive_items)
    print(f"\n脱敏结果:")
    print(f"原始: {test_text}")
    print(f"脱敏: {masked_text}")
    
    # 检查脱敏规则
    print(f"\n脱敏规则:")
    for rule_type, rule_func in masker.masking_rules.items():
        print(f"  - {rule_type}: {rule_func.__name__}")

if __name__ == "__main__":
    debug_masking()
