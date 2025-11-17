import re
import json
import yaml
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from config import SensitivityLevel, ActionType, SensitiveInfo

@dataclass
class CustomRule:
    """自定义规则数据结构"""
    name: str
    description: str
    pattern: str
    sensitivity_level: SensitivityLevel
    action_type: ActionType
    threshold: float = 0.8
    validation_function: Optional[str] = None
    masking_pattern: Optional[str] = None
    test_samples: List[Dict[str, Any]] = None

class CustomRuleParser:
    """自定义规则解析器"""
    
    def __init__(self):
        self.supported_formats = ['json', 'yaml', 'txt']
    
    def parse_json_rules(self, content: str) -> List[CustomRule]:
        """解析JSON格式的规则"""
        try:
            data = json.loads(content)
            rules = []
            
            if isinstance(data, list):
                for rule_data in data:
                    rules.append(self._parse_rule_data(rule_data))
            elif isinstance(data, dict):
                rules.append(self._parse_rule_data(data))
            
            return rules
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON格式错误: {e}")
    
    def parse_yaml_rules(self, content: str) -> List[CustomRule]:
        """解析YAML格式的规则"""
        try:
            data = yaml.safe_load(content)
            rules = []
            
            if isinstance(data, list):
                for rule_data in data:
                    rules.append(self._parse_rule_data(rule_data))
            elif isinstance(data, dict):
                rules.append(self._parse_rule_data(data))
            
            return rules
        except yaml.YAMLError as e:
            raise ValueError(f"YAML格式错误: {e}")
    
    def parse_text_rules(self, content: str) -> List[CustomRule]:
        """解析文本格式的规则"""
        rules = []
        lines = content.strip().split('\n')
        
        current_rule = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('---'):
                if current_rule:
                    rules.append(self._parse_rule_data(current_rule))
                    current_rule = {}
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                current_rule[key] = value
        
        if current_rule:
            rules.append(self._parse_rule_data(current_rule))
        
        return rules
    
    def _parse_rule_data(self, rule_data: Dict[str, Any]) -> CustomRule:
        """解析单个规则数据"""
        required_fields = ['name', 'pattern', 'sensitivity_level', 'action_type']
        
        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"缺少必需字段: {field}")
        
        # 解析敏感级别
        sensitivity_level = self._parse_sensitivity_level(rule_data['sensitivity_level'])
        
        # 解析处置建议
        action_type = self._parse_action_type(rule_data['action_type'])
        
        # 解析测试样本
        test_samples = rule_data.get('test_samples', [])
        if isinstance(test_samples, str):
            test_samples = json.loads(test_samples)
        
        return CustomRule(
            name=rule_data['name'],
            description=rule_data.get('description', ''),
            pattern=rule_data['pattern'],
            sensitivity_level=sensitivity_level,
            action_type=action_type,
            threshold=float(rule_data.get('threshold', 0.8)),
            validation_function=rule_data.get('validation_function'),
            masking_pattern=rule_data.get('masking_pattern'),
            test_samples=test_samples
        )
    
    def _parse_sensitivity_level(self, level_str: str) -> SensitivityLevel:
        """解析敏感级别"""
        level_mapping = {
            'low': SensitivityLevel.LOW,
            'medium': SensitivityLevel.MEDIUM,
            'high': SensitivityLevel.HIGH,
            'critical': SensitivityLevel.CRITICAL,
            '低': SensitivityLevel.LOW,
            '中': SensitivityLevel.MEDIUM,
            '高': SensitivityLevel.HIGH,
            '极高': SensitivityLevel.CRITICAL
        }
        
        level_str = level_str.lower().strip()
        if level_str not in level_mapping:
            raise ValueError(f"无效的敏感级别: {level_str}")
        
        return level_mapping[level_str]
    
    def _parse_action_type(self, action_str: str) -> ActionType:
        """解析处置建议"""
        action_mapping = {
            'log_only': ActionType.LOG_ONLY,
            'mask_data': ActionType.MASK_DATA,
            'block_access': ActionType.BLOCK_ACCESS,
            'delete_data': ActionType.DELETE_DATA,
            'notify_admin': ActionType.NOTIFY_ADMIN,
            '仅记录': ActionType.LOG_ONLY,
            '数据脱敏': ActionType.MASK_DATA,
            '阻止访问': ActionType.BLOCK_ACCESS,
            '删除数据': ActionType.DELETE_DATA,
            '通知管理员': ActionType.NOTIFY_ADMIN
        }
        
        action_str = action_str.lower().strip()
        if action_str not in action_mapping:
            raise ValueError(f"无效的处置建议: {action_str}")
        
        return action_mapping[action_str]
    
    def validate_rule(self, rule: CustomRule) -> Tuple[bool, List[str]]:
        """验证规则的有效性"""
        errors = []
        
        # 验证规则名称
        if not rule.name or len(rule.name.strip()) == 0:
            errors.append("规则名称不能为空")
        
        # 验证正则表达式
        try:
            re.compile(rule.pattern)
        except re.error as e:
            errors.append(f"正则表达式无效: {e}")
        
        # 验证阈值
        if not (0.0 <= rule.threshold <= 1.0):
            errors.append("阈值必须在0.0到1.0之间")
        
        # 验证脱敏模式（如果提供）
        if rule.masking_pattern:
            # 检查是否包含{content}占位符（支持{content}、{content[...]}等格式）
            if '{content' not in rule.masking_pattern:
                errors.append("脱敏模式必须包含{content}占位符（例如：{content}、{content[:4]}、{content[-4:]}等）")
        
        # 验证测试样本
        if rule.test_samples:
            for i, sample in enumerate(rule.test_samples):
                if 'text' not in sample:
                    errors.append(f"测试样本{i+1}缺少text字段")
                if 'expected_match' not in sample:
                    errors.append(f"测试样本{i+1}缺少expected_match字段")
        
        return len(errors) == 0, errors
    
    def test_rule(self, rule: CustomRule, test_text: str) -> Dict[str, Any]:
        """测试规则"""
        try:
            pattern = re.compile(rule.pattern)
            matches = list(pattern.finditer(test_text))
            
            results = []
            for match in matches:
                results.append({
                    'content': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'confidence': rule.threshold
                })
            
            return {
                'success': True,
                'matches': results,
                'match_count': len(results)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'matches': [],
                'match_count': 0
            }

class CustomRuleManager:
    """自定义规则管理器"""
    
    def __init__(self):
        self.parser = CustomRuleParser()
    
    def parse_rules_from_content(self, content: str, format_type: str) -> List[CustomRule]:
        """从内容解析规则"""
        if format_type == 'json':
            return self.parser.parse_json_rules(content)
        elif format_type == 'yaml':
            return self.parser.parse_yaml_rules(content)
        elif format_type == 'txt':
            return self.parser.parse_text_rules(content)
        else:
            raise ValueError(f"不支持的格式: {format_type}")
    
    def validate_rules(self, rules: List[CustomRule]) -> Dict[str, Any]:
        """验证规则列表"""
        results = {
            'valid_rules': [],
            'invalid_rules': [],
            'total_count': len(rules)
        }
        
        for rule in rules:
            is_valid, errors = self.parser.validate_rule(rule)
            if is_valid:
                results['valid_rules'].append(rule)
            else:
                results['invalid_rules'].append({
                    'rule': rule,
                    'errors': errors
                })
        
        return results
    
    def test_rules(self, rules: List[CustomRule], test_text: str) -> Dict[str, Any]:
        """测试规则列表"""
        results = {
            'rule_tests': [],
            'total_matches': 0
        }
        
        for rule in rules:
            test_result = self.parser.test_rule(rule, test_text)
            test_result['rule_name'] = rule.name
            results['rule_tests'].append(test_result)
            results['total_matches'] += test_result['match_count']
        
        return results

# 示例规则格式
EXAMPLE_RULES = {
    'json': '''[
    {
        "name": "合同编号",
        "description": "识别符合年-月-四位数字格式的合同编号（例如：2024-05-1145）",
        "pattern": "\\b(19|20)\\d{2}-(0[1-9]|1[0-2])-[0-9]{4}\\b",
        "sensitivity_level": "medium",
        "action_type": "mask_data",
        "threshold": 0.85,
        "masking_pattern": "{content[:4]}-**-****",
        "test_samples": [
            {
                "text": "2024-05-1145",
                "expected_match": true,
                "sample_type": "positive"
            },
            {
                "text": "2024-13-9999",
                "expected_match": false,
                "sample_type": "negative"
            }
        ]
    }
]''',
    
    'yaml': '''- name: 合同编号
  description: 识别符合年-月-四位数字格式的合同编号（例如：2024-05-1145）
  pattern: "\\b(19|20)\\d{2}-(0[1-9]|1[0-2])-[0-9]{4}\\b"
  sensitivity_level: medium
  action_type: mask_data
  threshold: 0.85
  masking_pattern: "{content[:4]}-**-****"
  test_samples:
    - text: "2024-05-1145"
      expected_match: true
      sample_type: positive
    - text: "2024-13-9999"
      expected_match: false
      sample_type: negative''',
    
    'txt': '''# 自定义敏感信息规则
# 格式说明：
# name: 规则名称
# description: 规则描述
# pattern: 正则表达式
# sensitivity_level: 敏感级别 (low/medium/high/critical)
# action_type: 处置建议 (log_only/mask_data/block_access/delete_data/notify_admin)
# threshold: 识别阈值 (0.0-1.0)
# masking_pattern: 脱敏模式 (可选，使用{content}占位符)
# test_samples: 测试样本 (JSON格式)

---
name: 合同编号
description: 识别符合年-月-四位数字格式的合同编号（例如：2024-05-1145）
pattern: "\\b(19|20)\\d{2}-(0[1-9]|1[0-2])-[0-9]{4}\\b"
sensitivity_level: medium
action_type: mask_data
threshold: 0.85
masking_pattern: "{content[:4]}-**-****"
test_samples: [{"text": "2024-05-1145", "expected_match": true, "sample_type": "positive"}, {"text": "2024-13-9999", "expected_match": false, "sample_type": "negative"}]'''
}
