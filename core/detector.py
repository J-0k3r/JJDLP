import re
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from config import Config, SensitiveInfo, SensitivityLevel, ActionType
from core.custom_rules import CustomRule, CustomRuleManager

class SensitiveDataDetector:
    """敏感数据检测器（瘦身版：编排层）"""
    
    def __init__(self):
        # 轻量候选正则，用于初筛；真正校验交由 core/* 模块
        import re as _re
        from core import idcard, bankcard, phone, name, address, email, ip
        self._re = _re
        # 内置类型注册：候选pattern + 校验函数 + 默认级别/处置
        self.registry = {
            'ID_CARD': {
                'candidate': _re.compile(r'\b[0-9Xx]{18}\b'),
                'validator': idcard.is_idcard,
                'level': SensitivityLevel.HIGH,
                'action': ActionType.MASK_DATA,
            },
            'BANK_CARD': {
                'candidate': _re.compile(r'\b\d{16,19}\b'),
                'validator': bankcard.is_bankcard,
                'level': SensitivityLevel.HIGH,
                'action': ActionType.MASK_DATA,
            },
            'MOBILE_PHONE': {
                'candidate': _re.compile(r'\b1[3-9]\d{9}\b'),
                'validator': phone.is_phone,
                'level': SensitivityLevel.HIGH,
                'action': ActionType.MASK_DATA,
            },
            'EMAIL': {
                'candidate': _re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
                'validator': email.is_email,
                'level': SensitivityLevel.MEDIUM,
                'action': ActionType.MASK_DATA,
            },
            'IP_ADDRESS': {
                'candidate': _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
                'validator': ip.is_ip,
                'level': SensitivityLevel.LOW,
                'action': ActionType.MASK_DATA,
            },
            'NAME': {
                'candidate': _re.compile(r'[\u4e00-\u9fa5]{2,4}'),
                'validator': name.is_name,
                'level': SensitivityLevel.LOW,
                'action': ActionType.MASK_DATA,
            },
            'ADDRESS': {
                'candidate': _re.compile(r'[\u4e00-\u9fa5]+(?:省[\u4e00-\u9fa5]+市[\u4e00-\u9fa5]+区|市[\u4e00-\u9fa5]+区)'),
                'validator': address.is_address,
                'level': SensitivityLevel.LOW,
                'action': ActionType.MASK_DATA,
            },
        }
        self.custom_rules = []
        self.custom_rule_manager = CustomRuleManager()
    
    def _compile_patterns(self):
        # 已无需单独编译（初始化已编译 candidate）
        pass
    
    def detect_sensitive_data(self, text: str) -> List[SensitiveInfo]:
        """检测文本中的敏感数据 - 先候选命中，再调用core校验，避免重复规则源"""
        sensitive_items: List[SensitiveInfo] = []
        used_positions = set()
        if not text:
            return sensitive_items
        # 内置类型候选+校验
        for t, cfg in self.registry.items():
            try:
                for m in cfg['candidate'].finditer(text):
                    start, end = m.start(), m.end()
                    if self._is_position_overlapped(start, end, used_positions):
                        continue
                    content = m.group()
                    if not cfg['validator'](content):
                        continue
                    confidence = self._calculate_confidence(content, t)
                    sensitive_items.append(SensitiveInfo(
                        type=t,
                        content=content,
                        position=(start, end),
                        confidence=confidence,
                        level=cfg['level'],
                        action=cfg['action']
                    ))
                    used_positions.add((start, end))
            except Exception:
                continue
        # 自定义规则
        for custom_rule in self.custom_rules:
            try:
                pattern = self._re.compile(custom_rule.pattern)
                for match in pattern.finditer(text):
                    start, end = match.start(), match.end()
                    if self._is_position_overlapped(start, end, used_positions):
                        continue
                    confidence = custom_rule.threshold
                    if custom_rule.validation_function:
                        confidence = self._validate_with_custom_function(match.group(), custom_rule.validation_function, confidence)
                    sensitive_items.append(SensitiveInfo(
                        type=f"CUSTOM_{custom_rule.name}",
                        content=match.group(),
                        position=(start, end),
                        confidence=confidence,
                        level=custom_rule.sensitivity_level,
                        action=custom_rule.action_type
                    ))
                    used_positions.add((start, end))
            except self._re.error:
                continue
        return sensitive_items
    
    def _is_position_overlapped(self, start: int, end: int, used_positions: set) -> bool:
        """检查位置是否与已使用的位置重叠"""
        for used_start, used_end in used_positions:
            if not (end <= used_start or start >= used_end):
                return True
        return False
    
    def _is_reasonable_content(self, content: str, pattern_type: str) -> bool:
        """检查内容是否合理"""
        content = content.strip()
        
        # 基本长度检查
        if len(content) < 3:
            return False
        
        # 特定类型的合理性检查
        if pattern_type == 'ID_CARD':
            # 身份证号应该是18位
            if len(content) != 18:
                return False
            # 检查校验位
            if not self._validate_id_card(content):
                return False
                
        elif pattern_type == 'BANK_CARD':
            # 银行卡号长度检查
            if len(content) < 16 or len(content) > 19:
                return False
            # 简化验证：只检查是否为数字
            if not content.isdigit():
                return False
                
        elif pattern_type == 'MOBILE_PHONE':
            # 手机号应该是11位
            if len(content) != 11:
                return False
            # 检查运营商号段
            if not self._validate_mobile_phone(content):
                return False
        
        return True
    
    def _validate_id_card(self, id_card: str) -> bool:
        """验证身份证号格式"""
        if len(id_card) != 18:
            return False
        
        # 检查前17位是否为数字
        if not id_card[:17].isdigit():
            return False
        
        # 检查最后一位
        last_char = id_card[-1].upper()
        if last_char not in '0123456789X':
            return False
        
        # 简单的地区代码检查（前6位）
        region_code = id_card[:6]
        if not region_code.isdigit():
            return False
        
        return True
    
    def _validate_bank_card(self, card_number: str) -> bool:
        """验证银行卡号格式"""
        if not card_number.isdigit():
            return False
        
        # 检查长度
        if len(card_number) < 16 or len(card_number) > 19:
            return False
        
        # 简单的Luhn算法检查
        return self._luhn_check(card_number)
    
    def _validate_mobile_phone(self, phone: str) -> bool:
        """验证手机号格式"""
        if not phone.isdigit():
            return False
        
        if len(phone) != 11:
            return False
        
        # 检查运营商号段
        valid_prefixes = ['130', '131', '132', '133', '134', '135', '136', '137', '138', '139',
                         '150', '151', '152', '153', '155', '156', '157', '158', '159',
                         '180', '181', '182', '183', '184', '185', '186', '187', '188', '189']
        
        return phone[:3] in valid_prefixes
    
    def _luhn_check(self, card_number: str) -> bool:
        """Luhn算法检查银行卡号"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        return checksum % 10 == 0
    
    def _calculate_confidence(self, content: str, pattern_type: str) -> float:
        """简化置信度计算：基础0.8，长文本+0.1；关键类型+0.1"""
        base_confidence = 0.8
        if len(content) > 20:
            base_confidence += 0.1
        if pattern_type in ['ID_CARD', 'BANK_CARD']:
            base_confidence += 0.1
        return min(max(base_confidence, 0.0), 1.0)
    
    def _validate_with_custom_function(self, content: str, validation_function: str, base_confidence: float) -> float:
        """使用自定义验证函数验证内容"""
        try:
            func = (validation_function or '').strip().lower()
            ok = True
            if func in ('luhn', 'luhn_check', 'bank_luhn'):
                ok = self._luhn_check(content)
            elif func in ('id_checksum', 'id_check', 'idcard'):
                ok = self.validate_id_card(content)
            elif func in ('mobile_prefix', 'mobile', 'phone_prefix'):
                ok = self.validate_mobile_phone(content)
            else:
                # 未知校验函数名，保持原始置信度
                ok = True
            return base_confidence if ok else max(0.0, base_confidence - 0.5)
        except Exception:
            return base_confidence
    
    def load_custom_rules(self, rules: List[CustomRule]):
        """加载自定义规则"""
        self.custom_rules = rules
    
    def add_custom_rule(self, rule: CustomRule):
        """添加单个自定义规则"""
        self.custom_rules.append(rule)
    
    def remove_custom_rule(self, rule_name: str):
        """移除自定义规则"""
        self.custom_rules = [rule for rule in self.custom_rules if rule.name != rule_name]
    
    def get_custom_rules(self) -> List[CustomRule]:
        """获取所有自定义规则"""
        return self.custom_rules
    
    def test_custom_rules(self, test_text: str) -> Dict[str, Any]:
        """测试自定义规则"""
        return self.custom_rule_manager.test_rules(self.custom_rules, test_text)
    
    def validate_id_card(self, id_card: str) -> bool:
        """验证身份证号"""
        if len(id_card) != 18:
            return False
        
        # 身份证校验码计算
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_codes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
        
        try:
            sum_val = sum(int(id_card[i]) * weights[i] for i in range(17))
            check_code = check_codes[sum_val % 11]
            return id_card[17].upper() == check_code
        except:
            return False
    
    def validate_bank_card(self, card_number: str) -> bool:
        """验证银行卡号（Luhn算法）"""
        if not card_number.isdigit():
            return False
        
        # Luhn算法验证
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        return luhn_checksum(card_number) == 0
    
    def validate_mobile_phone(self, phone: str) -> bool:
        """验证手机号"""
        if not phone.isdigit() or len(phone) != 11:
            return False
        
        # 中国手机号段验证
        valid_prefixes = ['130', '131', '132', '133', '134', '135', '136', '137', '138', '139',
                         '150', '151', '152', '153', '155', '156', '157', '158', '159',
                         '180', '181', '182', '183', '184', '185', '186', '187', '188', '189',
                         '170', '171', '172', '173', '174', '175', '176', '177', '178']
        
        return phone[:3] in valid_prefixes

class DataMasker:
    """数据脱敏器"""
    
    def __init__(self):
        self.masking_rules = {
            'ID_CARD': self._mask_id_card,
            'BANK_CARD': self._mask_bank_card,
            'MOBILE_PHONE': self._mask_mobile_phone,
            'NAME': self._mask_name,
            'EMAIL': self._mask_email,
            'ADDRESS': self._mask_address,
            'IP_ADDRESS': self._mask_ip_address
        }
        self.custom_masking_rules = {}
    
    def mask_sensitive_data(self, text: str, sensitive_items: List[SensitiveInfo]) -> str:
        """对敏感数据进行脱敏处理"""
        # 过滤掉置信度太低或内容不合理的项目
        valid_items = []
        for item in sensitive_items:
            # 过滤掉明显不是敏感信息的内容
            if self._is_valid_sensitive_content(item):
                valid_items.append(item)
        
        # 按位置倒序排列，避免位置偏移问题
        sorted_items = sorted(valid_items, key=lambda x: x.position[0], reverse=True)
        
        masked_text = text
        for item in sorted_items:
            if item.action == ActionType.MASK_DATA:
                # 检查是否有自定义脱敏规则
                if item.type.startswith('CUSTOM_') and item.type in self.custom_masking_rules:
                    masked_content = self.custom_masking_rules[item.type](item.content)
                else:
                    masked_content = self.masking_rules.get(item.type, self._default_mask)(item.content)
                masked_text = masked_text[:item.position[0]] + masked_content + masked_text[item.position[1]:]
        
        return masked_text
    
    def _is_valid_sensitive_content(self, item: SensitiveInfo) -> bool:
        """检查是否为有效的敏感信息内容"""
        content = item.content.strip()
        
        # 过滤掉明显不是敏感信息的内容
        invalid_patterns = [
            r'^[身份证手机银行卡邮箱地址]号?$',  # 过滤"身份证号"、"手机号"等标签
            r'^[\u4e00-\u9fa5]{2,4}(?:号码?|号)$',  # 过滤"姓名"、"地址"等标签
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, content):
                return False
        
        # 检查内容长度：姓名允许2位起，其它类型至少3位
        if item.type == 'NAME':
            if len(content) < 2:
                return False
        else:
            if len(content) < 3:
                return False
            
        # 对于姓名，检查是否包含"号"、"码"等后缀
        if item.type == 'NAME' and any(suffix in content for suffix in ['号', '码', '地址', '邮箱']):
            return False
            
        # 对于地址，检查是否只是标签
        if item.type == 'ADDRESS' and any(suffix in content for suffix in ['号', '码', '身份证', '手机', '银行卡']):
            return False
        
        return True
    
    def _mask_id_card(self, id_card: str) -> str:
        """身份证号脱敏"""
        if len(id_card) >= 8:
            return id_card[:4] + '*' * (len(id_card) - 8) + id_card[-4:]
        return '*' * len(id_card)
    
    def _mask_bank_card(self, card_number: str) -> str:
        """银行卡号脱敏"""
        if len(card_number) >= 8:
            return card_number[:4] + '*' * (len(card_number) - 8) + card_number[-4:]
        return '*' * len(card_number)
    
    def _mask_mobile_phone(self, phone: str) -> str:
        """手机号脱敏"""
        if len(phone) == 11:
            return phone[:3] + '****' + phone[-4:]
        return '*' * len(phone)
    
    def _mask_name(self, name: str) -> str:
        """姓名脱敏：隐藏姓氏，保留名字，与 core.name.mask_name 一致"""
        try:
            from core import name as _name
            return _name.mask_name(name)
        except Exception:
            if len(name) >= 2:
                return '*' + name[1:]
            return '*'
    
    def _mask_email(self, email: str) -> str:
        """邮箱脱敏"""
        if '@' in email:
            local, domain = email.split('@', 1)
            if len(local) >= 2:
                masked_local = local[0] + '*' * (len(local) - 1)
                return f"{masked_local}@{domain}"
        return '*' * len(email)
    
    def _mask_address(self, address: str) -> str:
        """地址脱敏：将前缀中的 省/市/区 隐去为 *省/*市/*区，保留其后详细地址"""
        try:
            from core import address as _addr
            return _addr.mask_address(address)
        except Exception:
            return address
    
    def _mask_ip_address(self, ip: str) -> str:
        """IP地址脱敏"""
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.***"
        return '*' * len(ip)
    
    def _default_mask(self, content: str) -> str:
        """默认脱敏方式"""
        if len(content) >= 4:
            return content[:2] + '*' * (len(content) - 4) + content[-2:]
        return '*' * len(content)
    
    def add_custom_masking_rule(self, rule_name: str, masking_pattern: str):
        """添加自定义脱敏规则"""
        def custom_mask(content: str) -> str:
            try:
                # 处理脱敏模式，支持 {content}、{content[:n]}、{content[-n:]} 等格式
                import re
                result = masking_pattern
                
                # 匹配 {content[...]} 格式的表达式
                pattern = r'\{content(\[[^\]]+\])?\}'
                
                def replace_expr(match):
                    expr = match.group(0)  # 完整的匹配，如 {content[:4]} 或 {content}
                    
                    if expr == '{content}':
                        # 直接返回完整内容
                        return content
                    else:
                        # 提取切片表达式，如 [:4] 或 [-4:]
                        slice_expr = match.group(1)  # [:4] 或 [-4:]
                        if slice_expr:
                            try:
                                # 安全地执行切片操作
                                # 只允许 content 变量，使用 locals() 限制作用域
                                safe_dict = {'content': content}
                                # 执行 content[slice_expr]，例如 content[:4]
                                sliced = eval(f'content{slice_expr}', {"__builtins__": {}}, safe_dict)
                                return sliced
                            except Exception:
                                # 如果执行失败，返回默认值
                                return content
                        else:
                            return content
                
                # 替换所有匹配的表达式
                result = re.sub(pattern, replace_expr, result)
                return result
            except Exception as e:
                # 如果脱敏模式有错误，使用默认脱敏
                print(f"脱敏模式处理错误: {e}")
                return self._default_mask(content)
        
        self.custom_masking_rules[rule_name] = custom_mask
    
    def remove_custom_masking_rule(self, rule_name: str):
        """移除自定义脱敏规则"""
        if rule_name in self.custom_masking_rules:
            del self.custom_masking_rules[rule_name]

class RiskAssessment:
    """风险评估器"""
    
    def __init__(self):
        # 类型权重（用于计算基础分数，大幅降低以控制分数上限）
        self.type_weights = {
            'ID_CARD': 0.08,
            'BANK_CARD': 0.08,
            'MOBILE_PHONE': 0.06,
            'EMAIL': 0.04,
            'NAME': 0.02,
            'ADDRESS': 0.02,
            'IP_ADDRESS': 0.01,
            # 自定义规则使用默认权重
            'CUSTOM': 0.03
        }
        
        # 低敏感类型（只包含这些类型之一时视为无风险）
        self.low_sensitive_types = {'NAME', 'IP_ADDRESS', 'ADDRESS'}
        
        # 图片类型（单独加分，不参与组合计算）
        self.image_types = {'ID_CARD_IMAGE', 'BANK_CARD_IMAGE'}
    
    def assess_risk(self, sensitive_items: List[SensitiveInfo]) -> Dict[str, Any]:
        """评估风险等级"""
        if not sensitive_items:
            return {
                'risk_level': '无',
                'risk_score': 0.0,
                'high_risk_items': [],
                'recommendations': ['文件安全，无需特殊处理']
            }
        
        # 分离图片类型和其他类型
        image_items = []
        data_items = []
        for item in sensitive_items:
            if item.type in self.image_types:
                image_items.append(item)
            else:
                data_items.append(item)
        
        # 先统计所有类型（用于判断是否只有低敏感类型）
        all_type_counts = {}
        for item in data_items:
            all_type_counts[item.type] = all_type_counts.get(item.type, 0) + 1
        
        # 判断是否只包含一种低敏感类型
        all_types = set(all_type_counts.keys())
        non_low_types = [t for t in all_types if t not in self.low_sensitive_types]
        low_types_present = [t for t in all_types if t in self.low_sensitive_types]
        
        # 如果只有一种低敏感类型，且没有其他类型，视为无风险
        if len(all_types) == 1 and len(low_types_present) == 1 and len(non_low_types) == 0:
            risk_score = 0.0
            risk_level = '无'
        else:
            # 统计各类型数量（排除IP_ADDRESS，因为它在组合中不计算）
            type_counts = {}
            for item in data_items:
                if item.type != 'IP_ADDRESS':  # IP地址不参与组合计算
                    type_counts[item.type] = type_counts.get(item.type, 0) + 1
            
            # 计算组合分数
            risk_score = self._calculate_combination_score(type_counts)
            
            # 特殊处理：NAME + ADDRESS 至少中风险（>=10）
            if 'NAME' in type_counts and 'ADDRESS' in type_counts:
                if risk_score < 10.0:
                    risk_score = 10.0
                # NAME + ADDRESS 最高只能到高（30分），不能到极高
                if risk_score > 30.0:
                    risk_score = 30.0
            
            # 加上图片加分（身份证图片略高于身份证+姓名+地址，银行卡图片略高于银行卡+手机号）
            # 根据新的计算公式使用sqrt：身份证+姓名+地址（各1个）= (0.08+0.02+0.02)*1*1.6*1.0 ≈ 0.19
            # 银行卡+手机号（各1个）= (0.08+0.06)*1*1.3*1.0 ≈ 0.18
            image_score = 0.0
            for item in image_items:
                if item.type == 'ID_CARD_IMAGE':
                    # 身份证图片加分略高于身份证+姓名+地址（3种类型组合）的分数，设为0.20
                    image_score += 0.20
                elif item.type == 'BANK_CARD_IMAGE':
                    # 银行卡图片加分略高于银行卡+手机号（2种类型组合）的分数，设为0.19
                    image_score += 0.19
            risk_score += image_score
            
            # 确保分数不超过100
            risk_score = min(risk_score, 100.0)
            
            # 确定风险等级
            if risk_score >= 70.01:
                risk_level = '极高'
            elif risk_score >= 30.01:
                risk_level = '高'
            elif risk_score >= 10.01:
                risk_level = '中'
            elif risk_score >= 0.01:
                risk_level = '低'
            else:
                risk_level = '无'
        
        # 保留2位小数
        risk_score = round(risk_score, 2)
        
        # 收集高风险项
        high_risk_items = []
        for item in sensitive_items:
            if item.level in [SensitivityLevel.HIGH, SensitivityLevel.CRITICAL]:
                high_risk_items.append(item)
        
        # 生成建议
        recommendations = self._generate_recommendations(sensitive_items, risk_level)
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'high_risk_items': high_risk_items,
            'recommendations': recommendations
        }
    
    def _calculate_combination_score(self, type_counts: Dict[str, int]) -> float:
        """计算组合分数"""
        if not type_counts:
            return 0.0
        
        # 计算基础分数（各类型权重 * sqrt(数量)，使用平方根避免线性增长过快）
        import math
        base_score = 0.0
        total_count = 0
        
        for item_type, count in type_counts.items():
            # 获取类型权重
            weight = self._get_type_weight(item_type)
            # 如果是自定义规则，使用CUSTOM权重
            if item_type.startswith('CUSTOM_'):
                # 若未配置专属权重，降级为通用自定义权重
                if weight == 0.03:
                    weight = self.type_weights.get('CUSTOM', 0.03)
            
            # 使用sqrt(数量)而不是直接乘以数量，使增长更平缓
            # 对于大数量，sqrt增长比线性慢，但比对数快
            base_score += weight * math.sqrt(max(count, 1))
            total_count += count
        
        # 组合加成：类型越多，加成越大（进一步降低加成倍数）
        type_count = len(type_counts)
        if type_count == 1:
            # 单种类型：无加成
            combination_multiplier = 1.0
        elif type_count == 2:
            # 两种类型组合：1.3倍
            combination_multiplier = 1.3
        elif type_count == 3:
            # 三种类型组合：1.6倍
            combination_multiplier = 1.6
        else:
            # 四种及以上：2.0倍
            combination_multiplier = 2.0
        
        # 数量加成：数量越多，分数越高（使用以1000为底的对数函数，系数进一步降低）
        # log1000(x) = log10(x) / log10(1000) = log10(x) / 3
        # 使用更小的系数，使数量增长对分数影响更平缓
        count_multiplier = 1.0 + (math.log10(max(total_count, 1)) / 3.0) * 0.03
        
        # 最终分数
        final_score = base_score * combination_multiplier * count_multiplier
        
        return final_score

    def _get_type_weight(self, item_type: str) -> float:
        """从系统配置动态读取类型权重（存在则覆盖默认）。"""
        try:
            from models import SystemConfig
            key = f'weight_{item_type}'
            rec = SystemConfig.query.filter_by(config_key=key).first()
            if rec and rec.config_value:
                try:
                    return float(rec.config_value)
                except Exception:
                    pass
        except Exception:
            # 数据库不可用或循环导入失败时，退回默认
            pass
        return self.type_weights.get(item_type, 0.03)
    
    def _generate_recommendations(self, sensitive_items: List[SensitiveInfo], risk_level: str) -> List[str]:
        """生成处理建议"""
        recommendations = []
        
        if risk_level == '极高':
            recommendations.extend([
                '立即隔离文件，禁止访问',
                '通知安全管理员',
                '进行深度安全审计',
                '考虑数据删除或加密存储'
            ])
        elif risk_level == '高':
            recommendations.extend([
                '限制文件访问权限',
                '对敏感数据进行脱敏处理',
                '记录访问日志',
                '定期安全审查'
            ])
        elif risk_level == '中':
            recommendations.extend([
                '对敏感数据进行脱敏处理',
                '设置访问控制',
                '定期监控'
            ])
        elif risk_level == '低':
            recommendations.append('建议对敏感数据进行脱敏处理')
        else:  # 无
            recommendations.append('正常处理，保持监控')
        
        return recommendations
