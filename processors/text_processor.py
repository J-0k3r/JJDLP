# 纯文本敏感数据识别与脱敏模块

from core import idcard, bankcard, name, address, phone, email, ip

# 敏感类型及脱敏函数注册表，和csv/json一致
SENSITIVE_TYPE_FUNCS = {
    '身份证': idcard.is_idcard,
    '银行卡': bankcard.is_bankcard,
    '姓名': name.is_name,
    '地址': address.is_address,
    '手机号': phone.is_phone,
    '邮箱': email.is_email,
    'IP': ip.is_ip,
}
SENSITIVE_MASK_FUNCS = {
    '身份证': idcard.mask_idcard,
    '银行卡': bankcard.mask_bankcard,
    '姓名': name.mask_name,
    '地址': address.mask_address,
    '手机号': phone.mask_phone,
    '邮箱': email.mask_email,
    'IP': ip.mask_ip,
}
class TextProcessor:
    """
    面向单条纯文本，批量进行多种类型的识别与脱敏处理
    用于日志、聊天、web输入等少量文本数据场景
    """
    def __init__(self):
        pass
    def detect_sensitive(self, text: str):
        """
        识别当前文本中可能存在哪些类型的敏感数据
        返回：类型、内容的列表结构
        """
        results = []
        for stype, func in SENSITIVE_TYPE_FUNCS.items():
            if func(text):  # 支持一条文本判多种类型（互斥时处理优先级）
                results.append({'type': stype, 'content': text})
        return results
    def mask_sensitive(self, text: str):
        """
        对一条文本批量脱敏支持：
        只要命中相应类型立即调用脱敏后返回，优先顺序由注册表决定
        """
        masked = text
        for stype, func in SENSITIVE_TYPE_FUNCS.items():
            if func(text):
                mask_func = SENSITIVE_MASK_FUNCS[stype]
                masked = mask_func(text)
                break  # 命中后只脱敏一种类型防止多重不可逆
        return masked
