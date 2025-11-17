# 邮箱识别与脱敏
import re

def is_email(text: str) -> bool:
    """
    标准邮箱识别，兼容主流格式。
    """
    email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return bool(isinstance(text, str) and re.match(email_pattern, text))

def mask_email(text: str) -> str:
    """
    邮箱脱敏，前缀首字+***+原域名。
    """
    if is_email(text):
        local, domain = text.split('@', 1)
        if len(local) > 1:
            masked_local = local[0] + '***'
        else:
            masked_local = '*'
        return masked_local + '@' + domain
    return text

