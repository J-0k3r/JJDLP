# 中文姓名识别与脱敏
import re

COMMON_SURNAMES = set([
    '赵','钱','孙','李','周','吴','郑','王','冯','陈','褚','卫','蒋','沈','韩','杨','朱','秦','尤','许',
    '何','吕','施','张','孔','曹','严','华','金','魏','陶','姜','戚','谢','邹','喻','柏','水','窦','章','云',
    '苏','潘','葛','奚','范','彭','郎','鲁','韦','昌','马','苗','凤','花','方','俞','任','袁','柳','酆','鲍'
])

def is_name(text: str) -> bool:
    """
    简化姓名识别逻辑，仅判断2-4位中文且首字为常见姓氏。
    不考虑极少数民族超长姓名，也不考虑后缀数字等个案。
    """
    if not (isinstance(text, str) and 2 <= len(text) <= 4):
        return False
    if re.match(r'^[\u4e00-\u9fa5]{2,4}$', text):
        return text[0] in COMMON_SURNAMES
    return False

def mask_name(text: str) -> str:
    """
    姓名脱敏，首位变*。
    """
    if is_name(text):
        return '*' + text[1:]
    return text
