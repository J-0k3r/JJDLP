import os
import re
import json
import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class SensitivityLevel(Enum):
    """敏感信息级别"""
    LOW = "低"
    MEDIUM = "中"
    HIGH = "高"
    CRITICAL = "极高"

class ActionType(Enum):
    """处置建议类型"""
    LOG_ONLY = "仅记录"
    MASK_DATA = "数据脱敏"
    BLOCK_ACCESS = "阻止访问"
    DELETE_DATA = "删除数据"
    NOTIFY_ADMIN = "通知管理员"

@dataclass
class SensitiveInfo:
    """敏感信息数据结构"""
    type: str
    content: str
    position: tuple  # (start, end) 位置
    confidence: float
    level: SensitivityLevel
    action: ActionType

class Config:
    """系统配置"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///dlp_system.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 文件上传配置
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'json', 'csv', 'png', 'jpg', 'jpeg', 'gif', 'bmp'}
    
    # 敏感信息识别配置 - 按优先级排序（精确模式在前）
    SENSITIVE_PATTERNS = {
        'ID_CARD': {
            'pattern': r'\b(?:[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])\b',
            'level': SensitivityLevel.HIGH,
            'action': ActionType.MASK_DATA
        },
        'BANK_CARD': {
            'pattern': r'\b(?:4\d{15,18}|5[1-5]\d{14,17}|6\d{15,18}|3[47]\d{13,16})\b',
            'level': SensitivityLevel.HIGH,
            'action': ActionType.MASK_DATA
        },
        'MOBILE_PHONE': {
            'pattern': r'\b1[3-9]\d{9}\b',
            'level': SensitivityLevel.HIGH,
            'action': ActionType.MASK_DATA
        },
        'EMAIL': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'level': SensitivityLevel.MEDIUM,
            'action': ActionType.MASK_DATA
        },
        'IP_ADDRESS': {
            'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'level': SensitivityLevel.LOW,
            'action': ActionType.MASK_DATA
        },
        'NAME': {
            'pattern': r'\b[\u4e00-\u9fa5]{2,4}(?![号码地址])\b',
            'level': SensitivityLevel.LOW,
            'action': ActionType.MASK_DATA
        },
        # 'ADDRESS': {
        #     'pattern': r'\b[\u4e00-\u9fa5]{2,}(?:省|市|区|县|街道|路|小区|村|镇)(?:[\u4e00-\u9fa5\-\s]*?)(?=\s|$|[，。！？])\b',
        #     'level': SensitivityLevel.MEDIUM,
        #     'action': ActionType.MASK_DATA
        # },
    }
    
    # 代理配置
    PROXY_SETTINGS = {
        'enabled': False,
        'http_proxy': '',
        'https_proxy': ''
    }
    
    # 性能参数
    PERFORMANCE_SETTINGS = {
        'max_file_size': 16 * 1024 * 1024,  # 16MB
        'max_processing_time': 300,  # 5分钟
        'concurrent_tasks': 5
    }
    
    # PaddleOCR配置
    # 模型文件下载目录（相对于项目根目录）
    PADDLEOCR_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.paddleocr')
    
    # idcard_ocr API配置
    IDCARD_OCR_API_URL = os.environ.get('IDCARD_OCR_API_URL') or 'http://localhost:8088/predict'
    IDCARD_OCR_API_TIMEOUT = int(os.environ.get('IDCARD_OCR_API_TIMEOUT', 10))  # 超时时间（秒）