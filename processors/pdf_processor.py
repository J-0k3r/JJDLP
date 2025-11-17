# PDF文件敏感数据识别处理器
# 按文本对象、图片对象、表格对象分类处理

import PyPDF2
from core import idcard, bankcard, name, address, phone, email, ip

# 敏感类型和脱敏函数注册表
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
class PDFProcessor:
    """
    PDF文件敏感检测与脱敏：
    - 遍历所有页及每页文本，按敏感类型规则做逐行分类型识别
    - 可输出按页分结构化的敏感日志
    - 脱敏处理为原始字符串批量mask，不修改原PDF（二次导出需用其它库处理二进制）
    - 图片/表格判别支持留接口
    """
    def __init__(self):
        pass
    def detect_text_content(self, file_path: str):
        """
        遍历所有页面，逐行提取文本内容，一旦判为敏感则记录类型及内容
        返回：结构化敏感数据列表，每条含页码、分类、原内容
        """
        results = []
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for idx, page in enumerate(pdf_reader.pages):
                text = page.extract_text() or ''
                for stype, func in SENSITIVE_TYPE_FUNCS.items():
                    for line in text.split('\n'):
                        if func(line):
                            results.append({'page': idx+1, 'type': stype, 'content': line})
                            break  # 每行命中后不再判别其它类型
                # TODO: 这里还可提取图片/表格对象扩展识别
        return results
    def detect_tables(self, file_path: str):
        """
        识别PDF中的表格，并按规则检测敏感数据。
        """
        pass

    def detect_images(self, file_path: str):
        """
        PDF中的图片对象类型检测。
        """
        pass

    def mask_text_content(self, file_path: str):
        """
        返回PDF每页的脱敏后文本列表
        - 如需实际PDF二进制内容脱敏请结合pdfplumber等进行二次渲染
        """
        masked_texts = []
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for idx, page in enumerate(pdf_reader.pages):
                text = page.extract_text() or ''
                lines = text.split('\n')
                masked_lines = []
                for line in lines:
                    masked = line
                    for stype, func in SENSITIVE_TYPE_FUNCS.items():
                        if func(line):
                            mask_func = SENSITIVE_MASK_FUNCS[stype]
                            masked = mask_func(line)
                            break
                    masked_lines.append(masked)
                masked_texts.append({'page': idx+1, 'masked_lines': masked_lines})
                # TODO: 如果要支持表格或图片对象脱敏，在此补充对应逻辑
        return masked_texts  # 可供json导出
