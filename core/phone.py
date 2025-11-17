# 手机号识别与脱敏
import re

CHINA_MOBILE_PREFIXES = set([
    '130','131','132','133','134','135','136','137','138','139','150','151','152','153','155','156',
    '157','158','159','180','181','182','183','184','185','186','187','188','189','170','171','172','173','174','175','176','177','178'
])

def is_phone(text: str) -> bool:
    """
    只识别中国大陆11位手机号+常见号段
    """
    if not (isinstance(text, str) and len(text) == 11 and text.isdigit()):
        return False
    return text[:3] in CHINA_MOBILE_PREFIXES

def mask_phone(text: str) -> str:
    """
    手机号脱敏：前3后4，中间四位*。
    """
    if is_phone(text):
        return text[:3] + '****' + text[-4:]
    return text

