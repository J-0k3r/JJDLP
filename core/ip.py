# IP地址识别与脱敏
import re

def is_ipv4(text: str) -> bool:
    """判断IPv4地址"""
    pattern = r'^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$'
    return isinstance(text, str) and re.match(pattern, text)

def is_ipv6(text: str) -> bool:
    """判断IPv6地址（简单格式判断）"""
    pattern = r'^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$'
    return isinstance(text, str) and re.match(pattern, text)

def is_ip(text: str) -> bool:
    """
    综合判断IPv4或IPv6
    """
    return is_ipv4(text) or is_ipv6(text)

def mask_ip(text: str) -> str:
    """
    IP脱敏 IPv4保留前一段其余用*，IPv6只保留前两块
    """
    if is_ipv4(text):
        parts = text.split('.')
        return parts[0] + '.***.***.***'
    elif is_ipv6(text):
        parts = text.split(':')
        return ':'.join(parts[:2]) + ':****:****:****:****:****:****'
    return text

