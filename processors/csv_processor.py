import pandas as pd
from core import idcard, bankcard, name, address, phone, email, ip

# 各类敏感数据类型的检测与脱敏函数注册表
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

class CSVProcessor:
    """
    CSV文件敏感数据批量识别与脱敏处理器
    实现：
    - 只要列内有一条被某种敏感类型命中，则整列归为该敏感类型
    - 可批量对敏感整列做脱敏，快速高效
    """
    def __init__(self):
        pass
    def detect_sensitive_columns(self, file_path: str):
        """
        识别敏感列，每列遇到一条命中则全列归类该敏感类型。
        返回：{列名: 敏感类型}
        """
        df = pd.read_csv(file_path, dtype=str, na_filter=False)  # 全部按字符串读方便处理空值
        col_types = {}  # 存放每个敏感列的类型
        for col in df.columns:
            # 每一列只要有一条命中敏感类型即可整列归类
            for stype, func in SENSITIVE_TYPE_FUNCS.items():
                if df[col].apply(func).any():  # 只要有一条检测成功
                    col_types[col] = stype
                    break  # 一列只标一种类型，优先级见注册顺序
        return col_types
    def mask_sensitive_columns(self, file_path: str):
        """
        对属于敏感类型的整列做批量脱敏，构造结构化结果
        返回：
        - columns_sensitive_type: 敏感列及类型
        - masked_df: 脱敏后DataFrame
        - masked_csv_str: 脱敏后csv字符串，便于直接导出
        """
        df = pd.read_csv(file_path, dtype=str, na_filter=False)
        col_types = self.detect_sensitive_columns(file_path)
        df_masked = df.copy()
        for col, stype in col_types.items():
            mask_func = SENSITIVE_MASK_FUNCS[stype]
            # 每个敏感列批量apply脱敏（只有真正命中的才会变，其他原样）
            df_masked[col] = df_masked[col].apply(
                lambda x: mask_func(x) if SENSITIVE_TYPE_FUNCS[stype](x) else x
            )
        # 返回结构包含方便后续落库和前端导出
        return {
            'columns_sensitive_type': col_types,
            'masked_df': df_masked,
            'masked_csv_str': df_masked.to_csv(index=False, encoding='utf-8')
        }
