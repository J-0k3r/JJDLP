# 身份证识别与脱敏
import re

def is_idcard(text: str) -> bool:
    """
    判断输入是否身份证号，含长度、校验位。
    只考虑中国大陆18位身份证。
    """
    if not isinstance(text, str):
        return False
    if len(text) != 18:
        return False
    pattern = r'^[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]$'
    if not re.match(pattern, text):
        return False
    # 校验码算法
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    sum_val = sum(int(text[i]) * weights[i] for i in range(17))
    check_code = check_codes[sum_val % 11]
    return text[17].upper() == check_code

def mask_idcard(text: str) -> str:
    """
    脱敏身份证号，前4后4位保留中间全部*。
    """
    if is_idcard(text):
        return text[:4] + '*'*10 + text[-4:]
    return text
