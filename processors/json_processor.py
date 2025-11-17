import json
from core import idcard, bankcard, name, address, phone, email, ip

# 类型判断与脱敏函数注册表，同csv
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
class JSONProcessor:
    """
    JSON文件敏感数据批量识别与脱敏处理器
    对所有key遍历，只要一个value命中类型则全key归为该类型，并可批量脱敏
    """
    def __init__(self):
        pass
    def detect_sensitive_keys(self, file_path: str):
        """
        检查所有key，只要有value命中某类敏感即整key归为该类型，深度遍历字典
        返回：{key: 敏感类型}
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        sensitive_keys = {}
        def walk(d):
            # 递归遍历所有字典与列表
            if isinstance(d, dict):
                for k, v in d.items():
                    # 判断当前key下内容是否命中任一类型
                    for stype, func in SENSITIVE_TYPE_FUNCS.items():
                        if (isinstance(v, str) and func(v)) or (isinstance(v, list) and any(func(i) for i in v if isinstance(i, str))):
                            sensitive_keys[k] = stype
                            break
                    walk(v)  # 递归深入
            elif isinstance(d, list):
                for item in d:
                    walk(item)
        walk(data)
        return sensitive_keys
    def mask_sensitive_keys(self, file_path: str):
        """
        批量对所有敏感key做脱敏处理，输出处理后json结构。
        返回：
        - keys_sensitive_type: 敏感key归类
        - masked_data: 脱敏后数据
        - masked_json_str: 脱敏后json字符输出，便于导出
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        sensitive_keys = self.detect_sensitive_keys(file_path)
        def mask_walk(d):
            # 递归批量遍历，针对敏感key进行脱敏
            if isinstance(d, dict):
                for k, v in d.items():
                    if k in sensitive_keys:
                        func = SENSITIVE_TYPE_FUNCS[sensitive_keys[k]]
                        mask_func = SENSITIVE_MASK_FUNCS[sensitive_keys[k]]
                        if isinstance(v, str):
                            d[k] = mask_func(v) if func(v) else v
                        elif isinstance(v, list):
                            # 列表类型批量应用脱敏
                            d[k] = [mask_func(i) if func(i) else i for i in v]
                    mask_walk(d[k])  # 递归处理下一层
            elif isinstance(d, list):
                for item in d:
                    mask_walk(item)
        mask_data = json.loads(json.dumps(data))  # 深复制以免改原文件
        mask_walk(mask_data)
        return {
            'keys_sensitive_type': sensitive_keys,
            'masked_data': mask_data,
            'masked_json_str': json.dumps(mask_data, ensure_ascii=False, indent=2)
        }
