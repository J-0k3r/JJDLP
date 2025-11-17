from datetime import datetime, timezone, timedelta
from flask_sqlalchemy import SQLAlchemy
from config import SensitivityLevel, ActionType
from app import db

# 北京时间时区 (UTC+8)
BEIJING_TZ = timezone(timedelta(hours=8))

def beijing_now():
    """获取当前北京时间"""
    return datetime.now(BEIJING_TZ).replace(tzinfo=None)

# # 这里需要从app.py导入db，但为了避免循环导入，我们使用延迟导入
# db = None

# def init_db(app_db):
#     global db
#     db = app_db

class ScanHistory(db.Model):
    """扫描历史记录（包含文件识别和从文件上传的文本识别）"""
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, unique=True)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    scan_time = db.Column(db.DateTime, default=beijing_now)
    scan_status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    sensitive_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='无')  # 无、低、中、高、极高
    # 新增字段: 识别到所有敏感类型（逗号分隔字符串，例如 "身份证,银行卡"）
    sensitive_types = db.Column(db.String(255), default='', comment='识别出的所有敏感类型')
    
    # 关联的敏感信息记录
    sensitive_items = db.relationship('SensitiveItem', backref='scan', lazy=True, cascade='all, delete-orphan')

class SensitiveItem(db.Model):
    """敏感信息项目"""
    __tablename__ = 'sensitive_items'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False)
    sensitive_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    position_start = db.Column(db.Integer, nullable=False)
    position_end = db.Column(db.Integer, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    sensitivity_level = db.Column(db.Enum(SensitivityLevel), nullable=False)
    action_type = db.Column(db.Enum(ActionType), nullable=False)
    context = db.Column(db.Text)  # 上下文信息
    
class SecurityPolicy(db.Model):
    """安全策略配置"""
    __tablename__ = 'security_policies'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    sensitive_type = db.Column(db.String(50), nullable=False)
    sensitivity_level = db.Column(db.String(50), nullable=False)  # 改为String以支持自定义值
    action_type = db.Column(db.String(50), nullable=False)  # 改为String以支持自定义值
    threshold = db.Column(db.Float, default=0.8)  # 识别阈值
    enabled = db.Column(db.Boolean, default=True)
    created_time = db.Column(db.DateTime, default=beijing_now)
    updated_time = db.Column(db.DateTime, default=beijing_now, onupdate=beijing_now)

class SystemConfig(db.Model):
    """系统配置"""
    __tablename__ = 'system_config'
    
    id = db.Column(db.Integer, primary_key=True)
    config_key = db.Column(db.String(100), nullable=False, unique=True)
    config_value = db.Column(db.Text, nullable=False)
    config_type = db.Column(db.String(20), default='string')  # string, int, float, bool, json
    description = db.Column(db.Text)
    updated_time = db.Column(db.DateTime, default=beijing_now, onupdate=beijing_now)

class MaskingRule(db.Model):
    """脱敏规则"""
    __tablename__ = 'masking_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sensitive_type = db.Column(db.String(50), nullable=False)
    masking_pattern = db.Column(db.String(200), nullable=False)  # 脱敏模式，如：***1234
    masking_method = db.Column(db.String(50), nullable=False)  # replace, hash, encrypt
    enabled = db.Column(db.Boolean, default=True)
    created_time = db.Column(db.DateTime, default=beijing_now)

class BusinessFile(db.Model):
    """业务文件分类"""
    __tablename__ = 'business_files'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False)
    business_type = db.Column(db.String(100), nullable=False)  # 业务类型
    department = db.Column(db.String(100))  # 部门
    owner = db.Column(db.String(100))  # 负责人
    classification = db.Column(db.String(50))  # 文件分类
    retention_period = db.Column(db.Integer)  # 保留期限（天）
    notes = db.Column(db.Text)  # 备注
    created_time = db.Column(db.DateTime, default=beijing_now)
    # 新增：入库时间、处理建议、敏感等级
    entry_time = db.Column(db.DateTime, default=beijing_now)  # 入库时间
    processing_advice = db.Column(db.String(100))  # 处理建议
    sensitivity_level = db.Column(db.String(50))  # 敏感等级（低/中/高/极高）
    
    # 关联扫描记录
    scan = db.relationship('ScanHistory', backref='business_file')

class CustomSensitiveRule(db.Model):
    """自定义敏感信息规则"""
    __tablename__ = 'custom_sensitive_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # 规则名称
    description = db.Column(db.Text)  # 规则描述
    pattern = db.Column(db.Text, nullable=False)  # 正则表达式模式
    sensitivity_level = db.Column(db.Enum(SensitivityLevel), nullable=False)  # 敏感级别
    action_type = db.Column(db.Enum(ActionType), nullable=False)  # 处置建议
    threshold = db.Column(db.Float, default=0.8)  # 识别阈值
    validation_function = db.Column(db.Text)  # 自定义验证函数（可选）
    masking_pattern = db.Column(db.String(200))  # 脱敏模式
    enabled = db.Column(db.Boolean, default=True)  # 是否启用
    created_by = db.Column(db.String(100))  # 创建者
    created_time = db.Column(db.DateTime, default=beijing_now)
    updated_time = db.Column(db.DateTime, default=beijing_now, onupdate=beijing_now)
    
    # 测试样本
    test_samples = db.relationship('RuleTestSample', backref='rule', lazy=True, cascade='all, delete-orphan')

class RuleTestSample(db.Model):
    """规则测试样本"""
    __tablename__ = 'rule_test_samples'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('custom_sensitive_rules.id'), nullable=False)
    sample_text = db.Column(db.Text, nullable=False)  # 测试样本
    expected_match = db.Column(db.Boolean, default=True)  # 是否应该匹配
    sample_type = db.Column(db.String(20), default='positive')  # positive/negative
    created_time = db.Column(db.DateTime, default=beijing_now)

class AuditLog(db.Model):
    """审计日志"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100))
    action = db.Column(db.String(100), nullable=False)  # 操作类型
    resource = db.Column(db.String(200))  # 操作资源
    details = db.Column(db.Text)  # 详细信息
    ip_address = db.Column(db.String(45))  # IP地址
    user_agent = db.Column(db.String(500))  # 用户代理
    timestamp = db.Column(db.DateTime, default=beijing_now)
    result = db.Column(db.String(20), default='success')  # success, failure

class TextScanHistory(db.Model):
    """纯文本识别历史记录（webui直接文本识别写入）"""
    __tablename__ = 'text_scan_history'
    id = db.Column(db.Integer, primary_key=True)
    text_content = db.Column(db.Text, nullable=False)
    scan_time = db.Column(db.DateTime, default=beijing_now)
    sensitive_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='无')  # 无、低、中、高、极高
    # 新增字段: 识别到所有敏感类型（逗号分隔字符串）
    sensitive_types = db.Column(db.String(255), default='', comment='文本识别所有敏感类型')
    # 关联文本详细敏感子表
    sensitive_items = db.relationship('TextSensitiveItem', backref='scan', lazy=True, cascade='all, delete-orphan')

class TextSensitiveItem(db.Model):
    """纯文本敏感项"""
    __tablename__ = 'text_sensitive_items'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('text_scan_history.id'), nullable=False)
    sensitive_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    position_start = db.Column(db.Integer, nullable=False)
    position_end = db.Column(db.Integer, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    sensitivity_level = db.Column(db.Enum(SensitivityLevel), nullable=False)
    action_type = db.Column(db.Enum(ActionType), nullable=False)
    # context/扩展字段同文件表可选
