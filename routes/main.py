from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import hashlib
import json
import logging
import threading
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone, timedelta
from processors.file_processor import FileProcessorFactory
from core.detector import SensitiveDataDetector, DataMasker, RiskAssessment

# 北京时间时区 (UTC+8)
BEIJING_TZ = timezone(timedelta(hours=8))

def beijing_now():
    """获取当前北京时间"""
    return datetime.now(BEIJING_TZ).replace(tzinfo=None)
from core.custom_rules import CustomRuleManager, EXAMPLE_RULES
from models import db, ScanHistory, SensitiveItem, SecurityPolicy, SystemConfig, MaskingRule, BusinessFile, AuditLog, CustomSensitiveRule, RuleTestSample, TextScanHistory, TextSensitiveItem
from config import Config, SensitivityLevel, ActionType
from core.custom_rules import CustomRule as CRObject

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# 配置访问日志
def setup_access_logging():
    """配置访问日志到logs目录"""
    # 确保logs目录存在
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # 创建访问日志文件路径（按日期）
    today = datetime.now().strftime('%Y-%m-%d')
    access_log_file = os.path.join(log_dir, f'access_{today}.log')
    
    # 配置Werkzeug访问日志
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.INFO)
    
    # 清除已有的处理器（避免重复）
    werkzeug_logger.handlers.clear()
    
    # 使用RotatingFileHandler，每个文件最大10MB，保留5个备份
    file_handler = RotatingFileHandler(
        access_log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)
    
    # 设置日志格式（与Werkzeug默认格式类似）
    formatter = logging.Formatter(
        '%(message)s',
        datefmt=''
    )
    file_handler.setFormatter(formatter)
    
    # 添加处理器
    werkzeug_logger.addHandler(file_handler)
    
    # 同时保留控制台输出（可选）
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    werkzeug_logger.addHandler(console_handler)

# 设置访问日志
setup_access_logging()

# 初始化处理器
detector = SensitiveDataDetector()
file_processor_factory = FileProcessorFactory(detector)
masker = DataMasker()
risk_assessor = RiskAssessment()

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 文件清理函数
def delete_uploaded_file(file_path):
    """删除上传的文件（静默处理，不抛出异常）"""
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass  # 静默处理删除失败

def cleanup_upload_folder():
    """清理uploads目录中的所有文件（定时任务）"""
    try:
        upload_folder = app.config['UPLOAD_FOLDER']
        if os.path.exists(upload_folder):
            for filename in os.listdir(upload_folder):
                file_path = os.path.join(upload_folder, filename)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                except Exception:
                    pass  # 静默处理删除失败
    except Exception:
        pass

def start_cleanup_scheduler():
    """启动定时清理任务（每小时清理一次）"""
    def cleanup_loop():
        while True:
            time.sleep(3600)  # 每小时执行一次
            cleanup_upload_folder()
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()

# 启动定时清理任务（每小时清理一次uploads目录）
start_cleanup_scheduler()

# 预设键名常量
PRESET_KEYS = {
    'business_type': 'presets_business_type',
    'department': 'presets_department',
    'processing_advice': 'presets_processing_advice',
    'sensitivity_level': 'presets_sensitivity_level',
}

def get_preset_list(config_key: str):
    rec = SystemConfig.query.filter_by(config_key=config_key).first()
    if not rec:
        return []
    try:
        return json.loads(rec.config_value)
    except Exception:
        return []

def set_preset_list(config_key: str, values: list):
    rec = SystemConfig.query.filter_by(config_key=config_key).first()
    if not rec:
        rec = SystemConfig(config_key=config_key, config_value=json.dumps(values, ensure_ascii=False), config_type='json')
        db.session.add(rec)
    else:
        rec.config_value = json.dumps(values, ensure_ascii=False)
    db.session.commit()

def refresh_custom_rules():
    """从数据库加载启用的自定义规则到检测器与脱敏器"""
    try:
        rules = CustomSensitiveRule.query.filter_by(enabled=True).all()
        crs = []
        for r in rules:
            crs.append(CRObject(
                name=r.name,
                description=r.description or '',
                pattern=r.pattern,
                sensitivity_level=r.sensitivity_level,
                action_type=r.action_type,
                threshold=r.threshold or 0.8,
                validation_function=r.validation_function,
                masking_pattern=r.masking_pattern
            ))
            # 脱敏模式注册：使用 CUSTOM_<name> 作为类型键，和检测结果保持一致
            if r.masking_pattern:
                try:
                    masker.add_custom_masking_rule(f'CUSTOM_{r.name}', r.masking_pattern)
                except Exception:
                    pass
        detector.load_custom_rules(crs)
    except Exception:
        pass

@app.route('/api/presets', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_presets():
    """读取/新增/重命名/删除 下拉预设选项。GET返回全部，POST新增，PUT重命名，DELETE删除。"""
    if request.method == 'GET':
        data = {
            'business_type': get_preset_list(PRESET_KEYS['business_type']),
            'department': get_preset_list(PRESET_KEYS['department']),
            'processing_advice': get_preset_list(PRESET_KEYS['processing_advice']),
            'sensitivity_level': get_preset_list(PRESET_KEYS['sensitivity_level']),
        }
        return jsonify({'success': True, 'data': data})
    payload = request.get_json(silent=True) or {}
    field = payload.get('field')  # business_type/department/processing_advice/sensitivity_level
    key = PRESET_KEYS.get(field)
    if not key:
        return jsonify({'success': False, 'error': '参数错误'}), 400
    if request.method == 'POST':
        value = (payload.get('value') or '').strip()
        if not value:
            return jsonify({'success': False, 'error': '缺少value'}), 400
        cur = get_preset_list(key)
        if value not in cur:
            cur.append(value)
            set_preset_list(key, cur)
        return jsonify({'success': True, 'values': cur})
    if request.method == 'PUT':
        value = (payload.get('value') or '').strip()
        new_value = (payload.get('new_value') or '').strip()
        if not value or not new_value:
            return jsonify({'success': False, 'error': '缺少value或new_value'}), 400
        cur = get_preset_list(key)
        if value in cur:
            cur = [new_value if v == value else v for v in cur]
            set_preset_list(key, cur)
            return jsonify({'success': True, 'values': cur})
        return jsonify({'success': False, 'error': '原值不存在'}), 404
    if request.method == 'DELETE':
        value = (payload.get('value') or '').strip()
        if not value:
            return jsonify({'success': False, 'error': '缺少value'}), 400
        cur = get_preset_list(key)
        if value in cur:
            cur = [v for v in cur if v != value]
            set_preset_list(key, cur)
            return jsonify({'success': True, 'values': cur})
        return jsonify({'success': False, 'error': '要删除的值不存在'}), 404

def allowed_file(filename):
    """检查文件类型是否允许"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_file_hash(file_path):
    """计算文件哈希值"""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def log_audit(user_id, action, resource, details, ip_address, user_agent, result='success'):
    """记录审计日志"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        result=result
    )
    db.session.add(audit_log)
    db.session.commit()

def serialize_sensitive_items(items):
    """将敏感信息对象转为可序列化结构"""
    return [{
        'type': i.type,
        'content': i.content,
        'position': i.position,
        'confidence': i.confidence,
        'level': getattr(i.level, 'value', str(i.level)),
        'action': getattr(i.action, 'value', str(i.action))
    } for i in items]

def process_file_scan(file_storage, client_ip=None, user_agent=None):
    """复用文件扫描流程，返回结构化结果（用于 Web/UI 和 API）"""
    refresh_custom_rules()
    if not file_storage or file_storage.filename == '':
        return {'success': False, 'error': '未选择文件'}, 400
    if not allowed_file(file_storage.filename):
        return {'success': False, 'error': '不支持的文件类型'}, 400

    filename = secure_filename(file_storage.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_storage.save(file_path)

    file_hash = calculate_file_hash(file_path)
    existing_scan = ScanHistory.query.filter_by(file_hash=file_hash).first()
    if existing_scan:
        delete_uploaded_file(file_path)
        return {
            'success': False,
            'error': '该文件已扫描',
            'existing_scan_id': existing_scan.id
        }, 409

    ext = filename.rsplit('.', 1)[1].lower()
    file_size = os.path.getsize(file_path)
    scan_record = ScanHistory(
        file_name=filename,
        file_path=file_path,
        file_hash=file_hash,
        file_size=file_size,
        file_type=ext,
        scan_status='processing'
    )
    db.session.add(scan_record)
    db.session.commit()

    try:
        result = file_processor_factory.process_file(file_path)

        # 图片文件的降级处理（与 Web 逻辑保持一致）
        if scan_record.file_type in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']:
            if not result.get('success', False):
                try:
                    from processors.image_processor import classify_image
                    image_type = classify_image(file_path)
                    if image_type != "未知类型":
                        result['success'] = True
                        result['text'] = f"图片类型: {image_type}"
                        result['sensitive_items'] = []
                except Exception:
                    pass
            elif result.get('text', '').strip() == '':
                try:
                    from processors.image_processor import classify_image
                    image_type = classify_image(file_path)
                    if image_type != "未知类型":
                        result['text'] = f"图片类型: {image_type}"
                except Exception:
                    pass

        if result.get('success'):
            sensitive_items = result.get('sensitive_items', [])

            # 如果图片识别到身份证/银行卡图片，追加伪造的敏感项提示
            extracted_text = result.get('text', '')
            if '身份证图片' in extracted_text:
                from core.detector import SensitiveInfo
                idcard_image_item = SensitiveInfo(
                    type='ID_CARD_IMAGE',
                    content='身份证图片',
                    position=(0, len('身份证图片')),
                    confidence=0.95,
                    level=SensitivityLevel.HIGH,
                    action=ActionType.MASK_DATA
                )
                sensitive_items.append(idcard_image_item)

            if '银行卡图片' in extracted_text:
                from core.detector import SensitiveInfo
                bankcard_image_item = SensitiveInfo(
                    type='BANK_CARD_IMAGE',
                    content='银行卡图片',
                    position=(0, len('银行卡图片')),
                    confidence=0.95,
                    level=SensitivityLevel.HIGH,
                    action=ActionType.MASK_DATA
                )
                sensitive_items.append(bankcard_image_item)

            # 解析 PDF/DOCX 统计到的图片计数
            import re
            idcard_count_pattern = r'共有(\d+)张身份证图片'
            bankcard_count_pattern = r'共有(\d+)张银行卡图片'

            idcard_matches = re.findall(idcard_count_pattern, extracted_text)
            bankcard_matches = re.findall(bankcard_count_pattern, extracted_text)

            if idcard_matches:
                count = int(idcard_matches[0])
                for i in range(count):
                    from core.detector import SensitiveInfo
                    idcard_image_item = SensitiveInfo(
                        type='ID_CARD_IMAGE',
                        content=f'身份证图片（第{i+1}张）',
                        position=(0, 20),
                        confidence=0.95,
                        level=SensitivityLevel.HIGH,
                        action=ActionType.MASK_DATA
                    )
                    sensitive_items.append(idcard_image_item)

            if bankcard_matches:
                count = int(bankcard_matches[0])
                for i in range(count):
                    from core.detector import SensitiveInfo
                    bankcard_image_item = SensitiveInfo(
                        type='BANK_CARD_IMAGE',
                        content=f'银行卡图片（第{i+1}张）',
                        position=(0, 20),
                        confidence=0.95,
                        level=SensitivityLevel.HIGH,
                        action=ActionType.MASK_DATA
                    )
                    sensitive_items.append(bankcard_image_item)

            # 写入敏感项
            for item in sensitive_items:
                sensitive_item = SensitiveItem(
                    scan_id=scan_record.id,
                    sensitive_type=item.type,
                    content=item.content,
                    position_start=item.position[0],
                    position_end=item.position[1],
                    confidence=item.confidence,
                    sensitivity_level=item.level,
                    action_type=item.action
                )
                db.session.add(sensitive_item)

            # 风险评估
            risk_assessment = risk_assessor.assess_risk(sensitive_items)

            # 归并敏感类型
            type_set = []
            for it in sensitive_items:
                if it.type not in type_set:
                    type_set.append(it.type)

            scan_record.scan_status = 'completed'
            scan_record.sensitive_count = len(sensitive_items)
            scan_record.risk_level = risk_assessment['risk_level']
            scan_record.sensitive_types = ','.join(type_set)
            db.session.commit()

            log_audit(
                user_id='anonymous',
                action='file_scan',
                resource=filename,
                details=f"发现 {len(sensitive_items)} 条敏感信息",
                ip_address=client_ip or 'unknown',
                user_agent=user_agent or ''
            )

            delete_uploaded_file(file_path)

            sensitive_types_str = ','.join(type_set)
            return {
                'success': True,
                'scan_id': scan_record.id,
                'file_name': filename,
                'file_size': file_size,
                'file_type': ext,
                'risk_level': risk_assessment['risk_level'],
                'sensitive_count': len(sensitive_items),
                'sensitive_types': sensitive_types_str,
                'sensitive_items': serialize_sensitive_items(sensitive_items)
            }, 200

        scan_record.scan_status = 'failed'
        db.session.commit()
        delete_uploaded_file(file_path)
        error_msg = result.get("error", "未知错误")
        return {'success': False, 'error': error_msg}, 500

    except Exception as e:
        scan_record.scan_status = 'failed'
        db.session.commit()
        delete_uploaded_file(file_path)
        return {'success': False, 'error': str(e)}, 500

def process_text_scan_request(text_content, client_ip=None, user_agent=None, include_objects=False):
    """复用文本扫描逻辑，返回 JSON 友好结构"""
    refresh_custom_rules()
    if not text_content or not text_content.strip():
        return {'success': False, 'error': '文本内容不能为空'}, 400

    sensitive_items = detector.detect_sensitive_data(text_content)

    # 应用安全策略覆盖
    policies = SecurityPolicy.query.filter_by(enabled=True).all()
    policy_map = {p.sensitive_type: p for p in policies}
    for idx, item in enumerate(sensitive_items):
        if item.type in policy_map:
            policy = policy_map[item.type]
            if policy.action_type in [e.value for e in ActionType]:
                item.action = ActionType(policy.action_type)
            else:
                from dataclasses import replace
                sensitive_items[idx] = replace(item, action=policy.action_type)

    risk_assessment = risk_assessor.assess_risk(sensitive_items)

    type_set = []
    for it in sensitive_items:
        if it.type not in type_set:
            type_set.append(it.type)
    sensitive_types_str = ','.join(type_set)

    txt_record = TextScanHistory(
        text_content=text_content,
        sensitive_count=len(sensitive_items),
        risk_level=risk_assessment['risk_level'],
        sensitive_types=sensitive_types_str
    )
    db.session.add(txt_record)
    db.session.commit()

    for item in sensitive_items:
        txt_item = TextSensitiveItem(
            scan_id=txt_record.id,
            sensitive_type=item.type,
            content=item.content,
            position_start=item.position[0],
            position_end=item.position[1],
            confidence=item.confidence,
            sensitivity_level=item.level,
            action_type=item.action
        )
        db.session.add(txt_item)
    db.session.commit()

    log_audit(
        user_id='anonymous',
        action='text_scan',
        resource='text_input',
        details=f"发现 {len(sensitive_items)} 条敏感信息",
        ip_address=client_ip or 'unknown',
        user_agent=user_agent or ''
    )

    payload = {
        'success': True,
        'scan_id': txt_record.id,
        'text_content': text_content,
        'risk_level': risk_assessment['risk_level'],
        'risk_assessment': risk_assessment,
        'sensitive_count': len(sensitive_items),
        'sensitive_types': sensitive_types_str,
        'sensitive_items': serialize_sensitive_items(sensitive_items)
    }
    if include_objects:
        payload['sensitive_items_obj'] = sensitive_items
    return payload, 200

def process_masking_request(text_content=None, file_storage=None):
    """复用脱敏逻辑，支持文本或文件输入"""
    refresh_custom_rules()
    allowed_masking_extensions = {'txt', 'json', 'csv'}

    if file_storage and file_storage.filename:
        filename = secure_filename(file_storage.filename)
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        if file_ext not in allowed_masking_extensions:
            return {'success': False, 'error': f'文件格式不支持（仅 TXT/JSON/CSV），当前: {file_ext or "未知"}'}, 400

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_storage.save(file_path)
        result = file_processor_factory.process_file(file_path)
        if not result.get('success'):
            delete_uploaded_file(file_path)
            return {'success': False, 'error': result.get('error', '解析失败')}, 500

        sensitive_items = result.get('sensitive_items', [])
        masked_text = masker.mask_sensitive_data(result.get('text', ''), sensitive_items)
        delete_uploaded_file(file_path)
        return {
            'success': True,
            'file_name': filename,
            'original_text': result.get('text', ''),
            'masked_text': masked_text,
            'sensitive_items': serialize_sensitive_items(sensitive_items),
            'sensitive_items_obj': sensitive_items
        }, 200

    if text_content and text_content.strip():
        sensitive_items = detector.detect_sensitive_data(text_content)
        masked_text = masker.mask_sensitive_data(text_content, sensitive_items)
        return {
            'success': True,
            'original_text': text_content,
            'masked_text': masked_text,
            'sensitive_items': serialize_sensitive_items(sensitive_items),
            'sensitive_items_obj': sensitive_items
        }, 200

    return {'success': False, 'error': '请输入文本内容或上传文件'}, 400

@app.route('/')
def index():
    """首页，渲染敏感类型/风险全局分布（前端已支持，只补充后端）"""
    from collections import Counter
    all_scans = ScanHistory.query.all()
    stype_counts_global = Counter()
    risk_level_counts = Counter()
    for scan in all_scans:
        risk_level_counts[scan.risk_level] += 1
        if scan.sensitive_types:
            for tp in scan.sensitive_types.split(','):
                stype_counts_global[tp] += 1
    return render_template('index.html', stype_counts=stype_counts_global, risk_level_counts=risk_level_counts)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """文件上传与识别（页面）"""
    if request.method == 'POST':
        resp, status = process_file_scan(
            request.files.get('file'),
            client_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        if resp.get('success'):
            flash(f"文件扫描完成，发现 {resp.get('sensitive_count', 0)} 条敏感信息")
            return redirect(url_for('scan_result', scan_id=resp.get('scan_id')))

        if resp.get('existing_scan_id'):
            flash('该文件已经扫描过')
            return redirect(url_for('scan_result', scan_id=resp['existing_scan_id']))

        error_msg = resp.get('error', '文件处理失败')
        if status >= 500:
            flash(f"文件处理失败: {error_msg}")
        else:
            flash(error_msg)
    
    return render_template('upload.html')

def get_supported_sensitive_types():
    """获取所有支持的敏感信息类型（包括系统内置和自定义规则）"""
    types_list = []
    
    # 敏感级别到中文和颜色的映射
    level_map = {
        SensitivityLevel.LOW: {'text': '低', 'color': 'success'},
        SensitivityLevel.MEDIUM: {'text': '中', 'color': 'warning'},
        SensitivityLevel.HIGH: {'text': '高', 'color': 'danger'},
        SensitivityLevel.CRITICAL: {'text': '极高', 'color': 'danger'},
    }
    
    # 系统内置类型配置（仅用于显示，实际级别从detector.registry获取）
    builtin_types = {
        'ID_CARD': {'name': '身份证号', 'icon': 'person-badge'},
        'BANK_CARD': {'name': '银行卡号', 'icon': 'credit-card'},
        'ID_CARD_IMAGE': {'name': '身份证图片', 'icon': 'person-badge'},
        'BANK_CARD_IMAGE': {'name': '银行卡图片', 'icon': 'credit-card'},
        'MOBILE_PHONE': {'name': '手机号', 'icon': 'telephone'},
        'NAME': {'name': '姓名', 'icon': 'person'},
        'EMAIL': {'name': '邮箱地址', 'icon': 'envelope'},
        'IP_ADDRESS': {'name': 'IP地址', 'icon': 'globe'},
        'ADDRESS': {'name': '地址', 'icon': 'geo-alt'},
    }
    
    # 添加系统内置类型（从detector.registry获取）
    for type_key, type_info in builtin_types.items():
        # 检查是否在detector的registry中（图片类型除外）
        if type_key in detector.registry or type_key in ['ID_CARD_IMAGE', 'BANK_CARD_IMAGE']:
            # 获取敏感级别
            if type_key in detector.registry:
                level = detector.registry[type_key]['level']
            elif type_key in ['ID_CARD_IMAGE', 'BANK_CARD_IMAGE']:
                # 图片类型使用对应的文本类型的级别
                base_type = 'ID_CARD' if type_key == 'ID_CARD_IMAGE' else 'BANK_CARD'
                level = detector.registry[base_type]['level'] if base_type in detector.registry else SensitivityLevel.HIGH
            else:
                level = SensitivityLevel.MEDIUM
            
            level_info = level_map.get(level, {'text': '中', 'color': 'warning'})
            
            types_list.append({
                'type': type_key,
                'name': type_info['name'],
                'icon': type_info['icon'],
                'level': level_info['text'],
                'color': level_info['color'],
                'is_custom': False
            })
    
    # 添加启用的自定义规则类型
    custom_rules = CustomSensitiveRule.query.filter_by(enabled=True).all()
    for rule in custom_rules:
        level = rule.sensitivity_level
        level_info = level_map.get(level, {'text': str(level.value) if hasattr(level, 'value') else str(level), 'color': 'info'})
        
        types_list.append({
            'type': f'CUSTOM_{rule.name}',
            'name': f'{rule.name} (自定义)',
            'icon': 'tag',
            'level': level_info['text'],
            'color': level_info['color'],
            'is_custom': True
        })
    
    return types_list

@app.route('/text_scan', methods=['GET', 'POST'])
def text_scan():
    """文本扫描（webui，同步写入TextScanHistory/TextSensitiveItem）"""
    if request.method == 'POST':
        resp, status = process_text_scan_request(
            request.form.get('text_content', ''),
            client_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            include_objects=True
        )
        if resp.get('success'):
            return render_template('text_scan_result.html',
                                 text_content=resp.get('text_content', ''),
                                 sensitive_items=resp.get('sensitive_items_obj', []),
                                 risk_assessment=resp.get('risk_assessment'))
        flash(resp.get('error', '文本内容不能为空'))
        return render_template('text_scan.html')

    sensitive_types = get_supported_sensitive_types()
    return render_template('text_scan.html', sensitive_types=sensitive_types)

@app.route('/scan_result/<int:scan_id>')
def scan_result(scan_id):
    """扫描结果页面+明细导出CSV/PDF"""
    from flask import request, Response, render_template_string
    from collections import Counter
    export = request.args.get('export', '')
    scan_record = ScanHistory.query.get_or_404(scan_id)
    sensitive_items = SensitiveItem.query.filter_by(scan_id=scan_id).all()
    
    # 统计各敏感数据类型的数量
    type_counts = Counter(item.sensitive_type for item in sensitive_items)
    
    # 获取业务标记信息
    business_file = BusinessFile.query.filter_by(scan_id=scan_id).first()
    
    # 根据安全策略更新处置建议
    policies = SecurityPolicy.query.filter_by(enabled=True).all()
    policy_map = {p.sensitive_type: p for p in policies}
    
    # 重新计算风险评估
    sensitive_info_list = []
    for item in sensitive_items:
        from core.detector import SensitiveInfo
        # 获取安全策略中的处置建议
        action_value = item.action_type.value if hasattr(item.action_type, 'value') else str(item.action_type)
        if item.sensitive_type in policy_map:
            policy = policy_map[item.sensitive_type]
            action_value = policy.action_type
        
        sensitive_info = SensitiveInfo(
            type=item.sensitive_type,
            content=item.content,
            position=(item.position_start, item.position_end),
            confidence=item.confidence,
            level=item.sensitivity_level,
            action=action_value  # 使用策略中的处置建议
        )
        sensitive_info_list.append(sensitive_info)
    risk_assessment = risk_assessor.assess_risk(sensitive_info_list)
    # 导出CSV
    if export == 'csv':
        import io, csv
        output = io.StringIO()
        from core import idcard, bankcard, name, address, phone, email, ip
        mask_funcs = {
            '身份证': idcard.mask_idcard,
            '银行卡': bankcard.mask_bankcard,
            '姓名': name.mask_name,
            '地址': address.mask_address,
            '手机号': phone.mask_phone,
            '邮箱': email.mask_email,
            'IP': ip.mask_ip,
        }
        writer = csv.writer(output)
        writer.writerow(["类型", "原文内容", "脱敏后", "置信度", "风险等级", "起始位置", "结束位置"])
        for item in sensitive_items:
            show_type = item.sensitive_type
            if show_type in mask_funcs:
                masked = mask_funcs[show_type](item.content)
            else:
                masked = ''
            writer.writerow([
                show_type,
                item.content,
                masked,
                f'{item.confidence:.2f}',
                item.sensitivity_level.value,
                item.position_start,
                item.position_end
            ])
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv', headers={
            "Content-Disposition": f"attachment;filename=dlp_sensitive_detail_{scan_id}.csv"
        })
    # 导出PDF功能
    if export == 'pdf':
        try:
            import pdfkit
            html = render_template_string('''<html><head><meta charset="utf-8"><title>敏感明细PDF</title></head><body>
            <h2>文件: {{ scan_record.file_name }}</h2><p>时间: {{ scan_record.scan_time.strftime('%Y-%m-%d %H:%M') }}</p>
            <h4>风险等级: {{ risk_assessment.risk_level }} | 敏感类型: {{ scan_record.sensitive_types }}</h4>
            <table border="1" cellpadding="3" cellspacing="0"><tr><th>类型</th><th>原文</th><th>脱敏后</th><th>置信度</th><th>风险</th><th>位置</th></tr>
            {% for item in sensitive_items %}<tr><td>{{ item.sensitive_type }}</td><td>{{ item.content }}</td><td>{{ mask_funcs[item.sensitive_type](item.content) if item.sensitive_type in mask_funcs else '' }}</td><td>{{ '%.2f' % item.confidence }}</td><td>{{ item.sensitivity_level.value }}</td><td>{{ item.position_start }}-{{ item.position_end }}</td></tr>{% endfor %}
            </table></body></html>''',
            scan_record=scan_record, sensitive_items=sensitive_items, risk_assessment=risk_assessment,
            mask_funcs=mask_funcs)
            pdf_bytes = pdfkit.from_string(html, False)
            return Response(pdf_bytes, mimetype='application/pdf', headers={
                "Content-Disposition": f"attachment;filename=dlp_sensitive_detail_{scan_id}.pdf"
            })
        except Exception as e:
            return f'PDF导出失败: {e}', 500
    # 为模板准备处置建议映射
    policy_map_for_template = {p.sensitive_type: p.action_type for p in policies}
    
    return render_template('scan_result.html',
                         scan_record=scan_record,
                         sensitive_items=sensitive_items,
                         risk_assessment=risk_assessment,
                         type_counts=type_counts,
                         business_file=business_file,
                         policy_action_map=policy_map_for_template)

@app.route('/history')
def scan_history():
    """
    扫描历史页面：支持敏感类型筛选、聚合统计、导出CSV，顶部聚合区
    """
    from collections import Counter
    from sqlalchemy import or_, and_
    page = request.args.get('page', 1, type=int)
    file_type = request.args.get('file_type', '').lower()
    status = request.args.get('status', '').lower()
    risk = request.args.get('risk', '')  # 风险等级现在是中文，不需要lower()
    stype = request.args.get('stype', '')
    department = request.args.get('department', '')
    business_type = request.args.get('business_type', '')
    export = request.args.get('export', '')

    # 构造query多条件过滤
    query = ScanHistory.query
    if file_type:
        query = query.filter_by(file_type=file_type)
    if status:
        query = query.filter_by(scan_status=status)
    if risk:
        query = query.filter_by(risk_level=risk)
    if stype:
        query = query.filter(ScanHistory.sensitive_types.like(f'%{stype}%'))
    
    # 部门和业务类型筛选（通过关联BusinessFile）
    if department or business_type:
        # 使用left join以保留所有扫描记录
        query = query.outerjoin(BusinessFile, ScanHistory.id == BusinessFile.scan_id)
        if department:
            if department == 'unmarked':
                query = query.filter(BusinessFile.department.is_(None))
            else:
                query = query.filter(BusinessFile.department == department)
        if business_type:
            if business_type == 'unmarked':
                query = query.filter(BusinessFile.business_type.is_(None))
            else:
                query = query.filter(BusinessFile.business_type == business_type)
    
    query = query.order_by(ScanHistory.scan_time.desc())
    scans_paginated = query.paginate(page=page, per_page=20, error_out=False)
    scans_page_list = scans_paginated.items
    
    # 为每个扫描记录获取业务信息
    for scan in scans_page_list:
        scan.business_info = BusinessFile.query.filter_by(scan_id=scan.id).first()

    # 本页聚合
    stype_counts = {}
    sensitive_types_all = set()
    for scan in scans_page_list:
        if scan.sensitive_types:
            for tp in scan.sensitive_types.split(','):
                sensitive_types_all.add(tp)
                stype_counts[tp] = stype_counts.get(tp, 0) + 1
    sensitive_types_all = sorted([tp for tp in sensitive_types_all if tp])

    # 获取所有可用的部门和业务类型（用于筛选下拉框）
    all_departments = db.session.query(BusinessFile.department).distinct().filter(BusinessFile.department.isnot(None)).all()
    departments_list = sorted([d[0] for d in all_departments if d[0]])
    
    all_business_types = db.session.query(BusinessFile.business_type).distinct().filter(BusinessFile.business_type.isnot(None)).all()
    business_types_list = sorted([bt[0] for bt in all_business_types if bt[0]])

    # 全局风险/类型分布（history顶部汇总条用）
    all_scans = ScanHistory.query.all()
    stype_counts_global = Counter()
    risk_level_counts = Counter()
    for scan in all_scans:
        risk_level_counts[scan.risk_level] += 1
        if scan.sensitive_types:
            for tp in scan.sensitive_types.split(','):
                stype_counts_global[tp] += 1

    # 导出功能（CSV）- 包含当前筛选结果的所有字段
    if export == 'csv':
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["扫描时间", "文件名", "文件类型", "风险等级", "敏感类型", "敏感数量", "文件大小(MB)", "业务类型", "所属部门"])
        for scan in scans_page_list:
            business_info = BusinessFile.query.filter_by(scan_id=scan.id).first()
            writer.writerow([
                scan.scan_time.strftime('%Y-%m-%d %H:%M'),
                scan.file_name,
                scan.file_type,
                scan.risk_level,
                scan.sensitive_types or '',
                scan.sensitive_count,
                f'{scan.file_size/1024/1024:.2f}',
                business_info.business_type if business_info else '未标记',
                business_info.department if business_info else '未标记'
            ])
        output.seek(0)
        from flask import Response
        return Response(output.getvalue(), mimetype='text/csv', headers={
            "Content-Disposition": "attachment;filename=dlp_scan_history.csv"
        })

    return render_template('history.html', 
                         scans=scans_paginated, 
                         sensitive_types_all=sensitive_types_all, 
                         stype_counts=stype_counts, 
                         stype_counts_global=stype_counts_global, 
                         risk_level_counts=risk_level_counts,
                         departments_list=departments_list,
                         business_types_list=business_types_list)

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def api_delete_history(scan_id):
    """删除单条扫描历史记录API"""
    try:
        scan_record = ScanHistory.query.get_or_404(scan_id)
        
        # 删除关联的敏感信息项
        SensitiveItem.query.filter_by(scan_id=scan_id).delete()
        
        # 删除关联的业务文件分类
        BusinessFile.query.filter_by(scan_id=scan_id).delete()
        
        # 删除扫描记录本身
        db.session.delete(scan_record)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '记录已删除'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/history/clear', methods=['DELETE'])
def api_clear_history():
    """清空所有扫描历史记录API"""
    try:
        # 删除所有关联的敏感信息项
        SensitiveItem.query.delete()
        
        # 删除所有关联的业务文件分类
        BusinessFile.query.delete()
        
        # 删除所有扫描记录
        deleted_count = ScanHistory.query.count()
        ScanHistory.query.delete()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'已清空 {deleted_count} 条记录'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/masking', methods=['GET', 'POST'])
def data_masking():
    """数据脱敏服务"""
    if request.method == 'POST':
        text_content = request.form.get('text_content', '')
        file_obj = request.files.get('file')
        resp, status = process_masking_request(text_content=text_content, file_storage=file_obj)

        if resp.get('success'):
            return render_template(
                'masking_result.html',
                original_text=resp.get('original_text', ''),
                masked_text=resp.get('masked_text', ''),
                sensitive_items=resp.get('sensitive_items_obj', []),
                file_name=resp.get('file_name')
            )

        flash(resp.get('error', '脱敏处理失败'))
    
    return render_template('masking.html')

@app.route('/config')
def system_config():
    """系统配置页面"""
    configs = SystemConfig.query.all()
    policies = SecurityPolicy.query.all()
    
    # 加载配置值到字典
    config_dict = {}
    for config in configs:
        config_dict[config.config_key] = config.config_value
    
    return render_template('config.html', configs=configs, policies=policies, config_dict=config_dict)

@app.route('/api/policy/add', methods=['POST'])
def api_add_policy():
    """添加安全策略API"""
    try:
        name = request.form.get('name')
        description = request.form.get('description', '')
        sensitive_type = request.form.get('sensitive_type')
        sensitivity_level_str = request.form.get('sensitivity_level')
        action_type_str = request.form.get('action_type')
        threshold = float(request.form.get('threshold', 0.8))
        enabled = request.form.get('enabled') == 'on'
        
        if not name or not sensitive_type or not sensitivity_level_str or not action_type_str:
            return jsonify({'success': False, 'error': '缺少必需参数'}), 400
        
        # 检查策略名称是否已存在
        existing = SecurityPolicy.query.filter_by(name=name).first()
        if existing:
            return jsonify({'success': False, 'error': '策略名称已存在'}), 400
        
        # 支持枚举值和自定义字符串值
        # 如果是枚举值（如LOW, MEDIUM等），尝试转换为枚举；否则直接使用字符串
        sensitivity_level = sensitivity_level_str
        try:
            # 尝试转换为枚举类型
            enum_level = SensitivityLevel[sensitivity_level_str]
            sensitivity_level = enum_level.value  # 使用枚举的值（中文）
        except KeyError:
            # 如果不是枚举值，直接使用字符串（自定义值）
            pass
        
        action_type = action_type_str
        try:
            # 尝试转换为枚举类型
            enum_action = ActionType[action_type_str]
            action_type = enum_action.value  # 使用枚举的值（中文）
        except KeyError:
            # 如果不是枚举值，直接使用字符串（自定义值）
            pass
        
        # 创建策略
        policy = SecurityPolicy(
            name=name,
            description=description,
            sensitive_type=sensitive_type,
            sensitivity_level=sensitivity_level,
            action_type=action_type,
            threshold=threshold,
            enabled=enabled
        )
        
        db.session.add(policy)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '策略添加成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/policy/<int:policy_id>', methods=['GET'])
def api_get_policy(policy_id):
    """获取单个安全策略API"""
    try:
        policy = SecurityPolicy.query.get(policy_id)
        if not policy:
            return jsonify({'success': False, 'error': '策略不存在'}), 404
        
        policy_data = {
            'id': policy.id,
            'name': policy.name,
            'description': policy.description,
            'sensitive_type': policy.sensitive_type,
            'sensitivity_level': policy.sensitivity_level,
            'action_type': policy.action_type,
            'threshold': policy.threshold,
            'enabled': policy.enabled
        }
        
        return jsonify({'success': True, 'policy': policy_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/policy/update', methods=['PUT'])
def api_update_policy():
    """更新安全策略API"""
    try:
        policy_id = request.form.get('policy_id')
        if not policy_id:
            return jsonify({'success': False, 'error': '缺少策略ID'}), 400
        
        policy = SecurityPolicy.query.get(policy_id)
        if not policy:
            return jsonify({'success': False, 'error': '策略不存在'}), 404
        
        name = request.form.get('name')
        description = request.form.get('description', '')
        sensitive_type = request.form.get('sensitive_type')
        sensitivity_level_str = request.form.get('sensitivity_level')
        action_type_str = request.form.get('action_type')
        threshold = float(request.form.get('threshold', 0.8))
        enabled = request.form.get('enabled') == 'on'
        
        if not name or not sensitive_type or not sensitivity_level_str or not action_type_str:
            return jsonify({'success': False, 'error': '缺少必需参数'}), 400
        
        # 检查策略名称是否已存在（排除自己）
        existing = SecurityPolicy.query.filter_by(name=name).first()
        if existing and existing.id != int(policy_id):
            return jsonify({'success': False, 'error': '策略名称已存在'}), 400
        
        # 支持枚举值和自定义字符串值
        sensitivity_level = sensitivity_level_str
        try:
            enum_level = SensitivityLevel[sensitivity_level_str]
            sensitivity_level = enum_level.value
        except KeyError:
            pass
        
        action_type = action_type_str
        try:
            enum_action = ActionType[action_type_str]
            action_type = enum_action.value
        except KeyError:
            pass
        
        # 更新策略
        policy.name = name
        policy.description = description
        policy.sensitive_type = sensitive_type
        policy.sensitivity_level = sensitivity_level
        policy.action_type = action_type
        policy.threshold = threshold
        policy.enabled = enabled
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': '策略更新成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/policy/delete', methods=['POST'])
def api_delete_policy():
    """删除安全策略API"""
    try:
        data = request.json
        policy_id = data.get('policy_id')
        
        if not policy_id:
            return jsonify({'success': False, 'error': '缺少策略ID'}), 400
        
        policy = SecurityPolicy.query.get(policy_id)
        if not policy:
            return jsonify({'success': False, 'error': '策略不存在'}), 404
        
        db.session.delete(policy)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '策略删除成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config/save', methods=['POST'])
def api_save_config():
    """保存系统配置API"""
    try:
        data = request.json
        category = data.get('category')  # system, proxy, performance
        config = data.get('config', {})
        
        if not category:
            return jsonify({'success': False, 'error': '缺少配置类别'}), 400
        
        # 保存配置到 SystemConfig 表
        for key, value in config.items():
            config_key = f'{category}_{key}'
            config_record = SystemConfig.query.filter_by(config_key=config_key).first()
            
            # 根据值的类型确定 config_type
            if isinstance(value, bool):
                config_type = 'bool'
                config_value = str(value)
            elif isinstance(value, int):
                config_type = 'int'
                config_value = str(value)
            elif isinstance(value, float):
                config_type = 'float'
                config_value = str(value)
            else:
                config_type = 'string'
                config_value = str(value)
            
            if config_record:
                config_record.config_value = config_value
                config_record.config_type = config_type
            else:
                config_record = SystemConfig(
                    config_key=config_key,
                    config_value=config_value,
                    config_type=config_type,
                    description=f'{category}配置: {key}'
                )
                db.session.add(config_record)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': '配置保存成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/custom_rules')
def api_custom_rules():
    """获取所有自定义规则（用于下拉选项）"""
    try:
        rules = CustomSensitiveRule.query.filter_by(enabled=True).all()
        rules_data = [{
            'id': r.id,
            'name': r.name,
            'description': r.description,
            'pattern': r.pattern,
            'sensitivity_level': r.sensitivity_level.value if r.sensitivity_level else None,
            'action_type': r.action_type.value if r.action_type else None,
            'threshold': r.threshold,
            'enabled': r.enabled
        } for r in rules]
        return jsonify({'success': True, 'rules': rules_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/business_classification/<int:scan_id>', methods=['GET', 'POST'])
def business_classification(scan_id):
    """业务文件分类页面"""
    scan_record = ScanHistory.query.get_or_404(scan_id)
    
    if request.method == 'POST':
        business_type = request.form.get('business_type')
        department = request.form.get('department')
        owner = request.form.get('owner')
        classification = request.form.get('classification')
        retention_period = request.form.get('retention_period', type=int)
        notes = request.form.get('notes')
        processing_advice = request.form.get('processing_advice')
        sensitivity_level = request.form.get('sensitivity_level')
        risk_level_manual = request.form.get('risk_level')
        entry_time_str = request.form.get('entry_time')
        if entry_time_str:
            try:
                entry_time_val = datetime.strptime(entry_time_str, '%Y-%m-%dT%H:%M')
            except Exception:
                entry_time_val = beijing_now()
            else:
                entry_time_val = beijing_now()
        
        # 创建或更新业务文件记录
        business_file = BusinessFile.query.filter_by(scan_id=scan_id).first()
        if not business_file:
            business_file = BusinessFile(scan_id=scan_id)
        
        business_file.business_type = business_type
        business_file.department = department
        business_file.owner = owner
        business_file.classification = classification
        business_file.retention_period = retention_period
        business_file.notes = notes
        business_file.processing_advice = processing_advice
        business_file.sensitivity_level = sensitivity_level
        business_file.entry_time = entry_time_val
        
        db.session.add(business_file)
        # 如手动设置了风险等级，则更新扫描记录的风险等级
        if risk_level_manual:
            scan_record.risk_level = risk_level_manual
            db.session.add(scan_record)
        db.session.commit()
        
        flash('业务文件分类信息已保存')
        return redirect(url_for('scan_result', scan_id=scan_id))
    
    business_file = BusinessFile.query.filter_by(scan_id=scan_id).first()
    
    return render_template('business_classification.html',
                         scan_record=scan_record,
                         business_file=business_file)

@app.route('/api/bulk_mark', methods=['POST'])
def api_bulk_mark():
    """批量标记API"""
    try:
        data = request.json
        scan_ids = data.get('scan_ids', [])
        if not scan_ids:
            return jsonify({'success': False, 'error': '请选择要标记的文件'}), 400
        
        # 获取标记信息
        business_type = data.get('business_type')
        department = data.get('department')
        owner = data.get('owner')
        classification = data.get('classification')
        retention_period = data.get('retention_period')
        notes = data.get('notes')
        processing_advice = data.get('processing_advice')
        sensitivity_level = data.get('sensitivity_level')
        entry_time_str = data.get('entry_time')
        
        if entry_time_str:
            try:
                entry_time_val = datetime.strptime(entry_time_str, '%Y-%m-%dT%H:%M')
            except Exception:
                entry_time_val = beijing_now()
            else:
                entry_time_val = beijing_now()
        
        # 批量应用到所有选中的扫描记录
        success_count = 0
        for scan_id in scan_ids:
            try:
                # 检查扫描记录是否存在
                scan_record = ScanHistory.query.get(scan_id)
                if not scan_record:
                    continue
                
                # 创建或更新业务文件记录
                business_file = BusinessFile.query.filter_by(scan_id=scan_id).first()
                if not business_file:
                    business_file = BusinessFile(scan_id=scan_id)
                
                business_file.business_type = business_type
                business_file.department = department
                business_file.owner = owner
                business_file.classification = classification
                if retention_period:
                    business_file.retention_period = int(retention_period)
                business_file.notes = notes
                business_file.processing_advice = processing_advice
                business_file.sensitivity_level = sensitivity_level
                business_file.entry_time = entry_time_val
                
                db.session.add(business_file)
                success_count += 1
            except Exception as e:
                print(f'Error marking scan {scan_id}: {e}')
                continue
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'成功标记 {success_count} 个文件',
            'count': success_count
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sensitive_types')
def api_sensitive_types():
    """获取支持的敏感信息类型API"""
    return jsonify(list(Config.SENSITIVE_PATTERNS.keys()))

@app.route('/api/weights', methods=['GET'])
def api_get_type_weights():
    """获取敏感类型权重（含自定义规则）"""
    try:
        # 1) 内置类型：从 detector.registry
        builtin_types = list(detector.registry.keys())
        # 加入图片类型（若需要单独配置）
        extra_types = ['ID_CARD_IMAGE', 'BANK_CARD_IMAGE']
        # 2) 自定义类型：启用的自定义规则
        custom_rules = CustomSensitiveRule.query.filter_by(enabled=True).all()
        custom_types = [f'CUSTOM_{r.name}' for r in custom_rules]
        all_types = builtin_types + extra_types + custom_types

        # 读取默认权重（用于参考）
        try:
            default_weights = dict(risk_assessor.type_weights)
        except Exception:
            default_weights = {}
        # 为图片类型提供默认（若需要）
        for extra in ['ID_CARD_IMAGE', 'BANK_CARD_IMAGE']:
            default_weights.setdefault(extra, None)

        # 读取当前已配置权重
        weights = {}
        for t in all_types:
            key = f'weight_{t}'
            rec = SystemConfig.query.filter_by(config_key=key).first()
            if rec and rec.config_value:
                try:
                    weights[t] = float(rec.config_value)
                except Exception:
                    continue
        return jsonify({'success': True, 'types': all_types, 'weights': weights, 'default_weights': default_weights})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/weights/save', methods=['POST'])
def api_save_type_weight():
    """保存单个敏感类型的权重"""
    try:
        data = request.json or {}
        t = (data.get('type') or '').strip()
        w = data.get('weight')
        if not t or w is None:
            return jsonify({'success': False, 'error': '缺少type或weight'}), 400
        try:
            w_val = float(w)
        except Exception:
            return jsonify({'success': False, 'error': 'weight需为数字'}), 400
        key = f'weight_{t}'
        rec = SystemConfig.query.filter_by(config_key=key).first()
        if not rec:
            rec = SystemConfig(config_key=key, config_value=str(w_val), config_type='float', description=f'{t} 类型权重')
            db.session.add(rec)
        else:
            rec.config_value = str(w_val)
            rec.config_type = 'float'
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan_stats')
def api_scan_stats():
    """获取扫描统计信息API"""
    total_scans = ScanHistory.query.count()
    completed_scans = ScanHistory.query.filter_by(scan_status='completed').count()
    failed_scans = ScanHistory.query.filter_by(scan_status='failed').count()
    
    risk_levels = db.session.query(ScanHistory.risk_level, db.func.count(ScanHistory.id)).group_by(ScanHistory.risk_level).all()
    
    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'risk_levels': dict(risk_levels)
    })

@app.route('/custom_rules', methods=['GET', 'POST'])
def custom_rules():
    """自定义敏感信息规则管理页面"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'import_rules':
            # 批量导入规则
            content = request.form.get('rules_content')
            format_type = request.form.get('format_type', 'json')
            
            try:
                rule_manager = CustomRuleManager()
                rules = rule_manager.parse_rules_from_content(content, format_type)
                validation_result = rule_manager.validate_rules(rules)
                
                if validation_result['invalid_rules']:
                    error_msg = "以下规则验证失败：\n"
                    for invalid_rule in validation_result['invalid_rules']:
                        error_msg += f"- {invalid_rule['rule'].name}: {', '.join(invalid_rule['errors'])}\n"
                    flash(error_msg, 'error')
                else:
                    # 保存有效规则
                    for rule in validation_result['valid_rules']:
                        db_rule = CustomSensitiveRule(
                            name=rule.name,
                            description=rule.description,
                            pattern=rule.pattern,
                            sensitivity_level=rule.sensitivity_level,
                            action_type=rule.action_type,
                            threshold=rule.threshold,
                            masking_pattern=rule.masking_pattern,
                            created_by='admin'
                        )
                        db.session.add(db_rule)
                    
                    db.session.commit()
                    flash(f'成功导入 {len(validation_result["valid_rules"])} 个规则')
                    
            except Exception as e:
                flash(f'规则导入失败: {str(e)}', 'error')
        
        return redirect(url_for('custom_rules'))
    
    # 获取所有自定义规则
    rules = CustomSensitiveRule.query.order_by(CustomSensitiveRule.created_time.desc()).all()
    
    return render_template('custom_rules.html', rules=rules, example_rules=EXAMPLE_RULES)

@app.route('/custom_rules/<int:rule_id>/delete', methods=['POST'])
def delete_custom_rule(rule_id):
    """删除自定义规则"""
    rule = CustomSensitiveRule.query.get_or_404(rule_id)
    
    db.session.delete(rule)
    db.session.commit()
    
    flash('规则删除成功')
    return redirect(url_for('custom_rules'))

@app.route('/custom_rules/<int:rule_id>/toggle', methods=['POST'])
def toggle_custom_rule(rule_id):
    """启用/禁用自定义规则"""
    rule = CustomSensitiveRule.query.get_or_404(rule_id)
    
    rule.enabled = not rule.enabled
    db.session.commit()
    
    status = '启用' if rule.enabled else '禁用'
    flash(f'规则已{status}')
    return redirect(url_for('custom_rules'))

@app.route('/custom_rules/dataset_test', methods=['POST'])
def custom_rules_dataset_test():
    """数据集测试：CSV列(rule_name,text,expected_match)"""
    try:
        import csv, io, re
        file = request.files.get('dataset')
        if not file:
            return jsonify({'success': False, 'error': '未上传文件'}), 400
        content = file.read().decode('utf-8', errors='ignore')
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        # 预取规则
        name_to_rule = {r.name: r for r in CustomSensitiveRule.query.filter_by(enabled=True).all()}
        total = 0
        correct = 0
        for row in rows:
            rule_name = (row.get('rule_name') or '').strip()
            text = row.get('text') or ''
            expected_str = (row.get('expected_match') or '').strip().lower()
            expected = True if expected_str in ['true', '1', 'yes', 'y', 't'] else False
            if not rule_name or rule_name not in name_to_rule:
                continue
            rule = name_to_rule[rule_name]
            try:
                pattern = re.compile(rule.pattern)
            except re.error:
                continue
            matched = bool(pattern.search(text))
            total += 1
            if matched == expected:
                correct += 1
        accuracy = (correct/total) if total else 0.0
        return jsonify({'success': True, 'total': total, 'correct': correct, 'incorrect': total-correct, 'accuracy': accuracy})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/manual_import', methods=['GET', 'POST'])
def manual_import():
    """手动导入敏感文件，仅保存基本信息，不做自动识别，跳转标记页面"""
    from werkzeug.utils import secure_filename
    import os
    from datetime import datetime
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('请选择要上传的文件')
            return redirect(request.url)
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # 处理文件名冲突（如果文件已存在，添加时间戳）
        if os.path.exists(file_path):
            base_name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{base_name}_{timestamp}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(file_path)
        file_stat = os.stat(file_path)
        file_hash = calculate_file_hash(file_path)
        
        # 检查是否已经存在相同哈希的文件（避免唯一约束冲突）
        existing_scan = ScanHistory.query.filter_by(file_hash=file_hash).first()
        if existing_scan:
            # 如果文件已存在（无论是手动导入还是自动扫描），删除刚上传的文件，使用现有记录
            delete_uploaded_file(file_path)
            flash('该文件已存在，将使用现有记录')
            return redirect(url_for('business_classification', scan_id=existing_scan.id))
        
        # 创建新的扫描记录
        scan_record = ScanHistory(
            file_name=filename,
            file_path=file_path,
            file_hash=file_hash,
            file_size=file_stat.st_size,
            file_type=filename.split('.')[-1].lower() if '.' in filename else '',
            scan_status='manual',
            scan_time=beijing_now(),
            sensitive_count=0,
            risk_level='低',
            sensitive_types='' 
        )
        
        try:
            db.session.add(scan_record)
            db.session.commit()
            
            # 手动导入后立即删除文件（业务分类页面不需要文件）
            # file_path已经在创建记录时保存了完整路径，删除文件后保留路径信息
            delete_uploaded_file(file_path)
            
            return redirect(url_for('business_classification', scan_id=scan_record.id))
        except Exception as e:
            db.session.rollback()
            # 如果仍然出现唯一约束错误，查找现有记录
            existing_scan = ScanHistory.query.filter_by(file_hash=file_hash).first()
            if existing_scan:
                flash('该文件已存在，将使用现有记录')
                return redirect(url_for('business_classification', scan_id=existing_scan.id))
            else:
                flash(f'保存文件记录失败: {str(e)}')
                return redirect(request.url)
    
    return render_template('manual_import.html')

# API 封装（JSON 版本）
@app.route('/api/upload', methods=['POST'])
def api_upload():
    resp, status = process_file_scan(
        request.files.get('file'),
        client_ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    return jsonify(resp), status

@app.route('/api/text_scan', methods=['POST'])
def api_text_scan():
    payload = request.get_json(silent=True) or {}
    text_content = request.form.get('text_content') or payload.get('text') or payload.get('text_content')
    resp, status = process_text_scan_request(
        text_content,
        client_ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    resp.pop('sensitive_items_obj', None)
    return jsonify(resp), status

@app.route('/api/masking', methods=['POST'])
def api_masking():
    payload = request.get_json(silent=True) or {}
    text_content = request.form.get('text_content') or payload.get('text') or payload.get('text_content')
    file_obj = request.files.get('file')
    resp, status = process_masking_request(text_content=text_content, file_storage=file_obj)
    resp.pop('sensitive_items_obj', None)
    return jsonify(resp), status

@app.route('/api/manual_upload', methods=['POST'])
def api_manual_upload():
    """手工标注文件和业务信息的接口"""
    data = request.form.to_dict() or request.get_json(silent=True) or {}
    req_fields = ['file_name', 'file_type']
    if not all(field in data for field in req_fields):
        return jsonify({'success': False, 'error': '缺少必填字段'}), 400

    file_path = data.get('file_path') or data['file_name']
    scan = ScanHistory(
        file_name=data['file_name'],
        file_path=file_path,
        file_hash=data.get('file_hash', ''),
        file_size=int(float(data.get('file_size', 0) or 0)),
        file_type=data['file_type'],
        scan_status='manual',
        sensitive_count=int(float(data.get('sensitive_count', 0) or 0)),
        risk_level=data.get('risk_level', '低'),
        sensitive_types=data.get('sensitive_types', '')
    )
    db.session.add(scan)
    db.session.commit()

    business = BusinessFile(
        scan_id=scan.id,
        business_type=data.get('business_type'),
        department=data.get('department'),
        owner=data.get('owner'),
        classification=data.get('classification'),
        retention_period=data.get('retention_period'),
        notes=data.get('notes'),
        processing_advice=data.get('processing_advice'),
        sensitivity_level=data.get('sensitivity_level')
    )
    db.session.add(business)
    db.session.commit()
    return jsonify({'success': True, 'scan_id': scan.id, 'msg': '自助录入成功'}), 200
# 404错误处理 - 忽略Chrome扩展等外部请求
@app.errorhandler(404)
def handle_404(error):
    """处理404错误，忽略Chrome扩展等外部请求"""
    # 如果是Chrome扩展或其他浏览器扩展的请求，静默忽略
    if request.path.startswith('/chrome-extension://') or \
       request.path.startswith('/extension://') or \
       request.path.startswith('/moz-extension://') or \
       'extension' in request.path.lower():
        return '', 204  # 返回204 No Content，静默忽略
    
    # 其他404请求正常处理
    return jsonify({'error': '资源未找到', 'path': request.path}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)





