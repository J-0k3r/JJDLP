# 地址识别与脱敏规则
import re

def is_address(text: str) -> bool:
    """
    匹配“XX省XX市XX区…”或“XX市XX区…”型。进一步识别详细为：省市区+任意若干（大于一的汉字+1-6数字+大于一的汉字），如“建国路88号”、“中山大道21栋805”等。
    """
    # 1. 基础省市区段
    pattern1 = r'([\u4e00-\u9fa5]+省[\u4e00-\u9fa5]+市[\u4e00-\u9fa5]+区)'
    pattern2 = r'([\u4e00-\u9fa5]+市[\u4e00-\u9fa5]+区)'
    # 2. 详细段一个完整详细地址元素：汉字2+ 数字1~6 汉字2+
    detail_pattern = r'[\u4e00-\u9fa5]{1,}\d{1,6}[\u4e00-\u9fa5]{1,}'
    # 完整组合：基础段 + 若干（详细段）
    if (m := re.search(pattern1, text)) or (m := re.search(pattern2, text)):
        idx = m.end()
        # 找详细段
        detail = ''
        rest = text[idx:]
        detail_match = re.findall(detail_pattern, rest)
        if detail_match:
            detail = ''.join(detail_match)  # 可多段拼接
            return True  # 认定整体是地址
        # 若找不到详细段，也认前缀是地址
        return True
    return False

def mask_address(text: str) -> str:
    """
    省市区部分脱敏为*省*市*区，后续数字全脱敏。
    """
    s = text
    # 替换省、市、区
    s = re.sub(r'^([\u4e00-\u9fa5]+)省', '*省', s)
    s = re.sub(r'^((\*省)?[\u4e00-\u9fa5]+)市', lambda m: (m.group(2) if m.group(2) else '') + '*市', s)
    s = re.sub(r'^((\*省)?(\*市)?[\u4e00-\u9fa5]+)区', lambda m: ''.join(i for i in [m.group(2), m.group(3)] if i) + '*区', s)
    # 替换所有数字为*
    s = re.sub(r'\d', '*', s)
    return s
