# 银行卡号识别与脱敏
import re

def luhn_check(card_number: str) -> bool:
    s = [int(ch) for ch in card_number[:-1][::-1]]
    check = int(card_number[-1])
    for i in range(len(s)):
        if i % 2 == 0:
            s[i] *= 2
            if s[i] > 9:
                s[i] -= 9
    return (sum(s) + check) % 10 == 0

def is_bankcard(text: str) -> bool:
    """
    判断是否为银行卡号（16、17或19位，纯数字，Luhn算法校验；18位直接排除）。
    """
    if not (isinstance(text, str) and text.isdigit() and len(text) in (16, 17, 19)):
        return False
    return luhn_check(text)

def mask_bankcard(text: str) -> str:
    """
    银行卡号脱敏，前4后4保留，中间全部*。
    """
    if is_bankcard(text):
        return text[:4] + '*' * (len(text) - 8) + text[-4:]
    return text
