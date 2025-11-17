# DLP 服务 API 文档

完整列出已实现的 HTTP 接口、参数说明和请求/响应示例，方便外部服务直接调用。默认 Base URL：`http://localhost:5000`（可按部署环境替换）。

## 通用信息
- 请求体编码：`application/json`，文件上传接口使用 `multipart/form-data`
- 返回格式：JSON，成功一般包含 `success: true`，失败包含 `success: false` 和 `error`
- 鉴权：当前版本未启用鉴权/Token，请根据需要在网关层补充
- 默认端口：`5000`（来自 `app.run(...)`）

---

## 1. 预置选项管理
### GET /api/presets
获取业务类型、部门、处置建议、敏感等级的预置下拉值。

**响应示例**
```json
{
  "success": true,
  "data": {
    "business_type": ["金融", "政务"],
    "department": ["风控部"],
    "processing_advice": ["告警", "阻断"],
    "sensitivity_level": ["低", "中", "高"]
  }
}
```

### POST /api/presets
新增预置值。
- body：`{ "field": "business_type|department|processing_advice|sensitivity_level", "value": "新增值" }`

**响应示例**
```json
{ "success": true, "values": ["金融", "政务", "新增值"] }
```

### PUT /api/presets
更新预置值。
- body：`{ "field": "...", "value": "旧值", "new_value": "新值" }`

### DELETE /api/presets
删除预置值。
- body：`{ "field": "...", "value": "要删除的值" }`

---

## 2. 扫描历史
### DELETE /api/history/<scan_id>
删除单条扫描记录及关联的敏感项、业务信息。

**响应示例**
```json
{ "success": true, "message": "记录已删除" }
```

### DELETE /api/history/clear
清空全部扫描历史（慎用）。
```json
{ "success": true, "message": "共清理 10 条记录" }
```

---

## 3. 安全策略
### POST /api/policy/add
新增策略。
- form-data/x-www-form-urlencoded：
  - `name`*：策略名（唯一）
  - `description`：描述
  - `sensitive_type`*：如 `ID_CARD`
  - `sensitivity_level`*：`low|medium|high` 或自定义字符串
  - `action_type`*：`mask_data|block_access|alert` 或自定义字符串
  - `threshold`：浮点，默认 0.8
  - `enabled`：`on` 表示启用

**响应示例**
```json
{ "success": true, "message": "策略添加成功" }
```

### GET /api/policy/<policy_id>
获取指定策略。
```json
{
  "success": true,
  "policy": {
    "id": 1,
    "name": "身份证策略",
    "sensitive_type": "ID_CARD",
    "sensitivity_level": "high",
    "action_type": "mask_data",
    "threshold": 0.9,
    "enabled": true
  }
}
```

### PUT /api/policy/update
更新策略。
- form-data：`policy_id`* 及上面字段

### POST /api/policy/delete
删除策略。
- form-data：`policy_id`*

---

## 4. 系统配置
### POST /api/config/save
批量保存配置项。
- JSON body：
```json
{
  "category": "system|proxy|performance",
  "config": {
    "key1": "value",
    "key2": 10,
    "key3": true
  }
}
```

**响应**：`{ "success": true, "message": "配置保存成功" }`

---

## 5. 自定义规则
### GET /api/custom_rules
获取已启用的自定义敏感规则列表。

**响应示例**
```json
{
  "success": true,
  "rules": [
    {
      "id": 1,
      "name": "自定义身份证",
      "description": "18 位数字，以 0 结尾",
      "pattern": "\\d{17}0",
      "sensitivity_level": "high",
      "action_type": "mask_data",
      "threshold": 0.85,
      "enabled": true
    }
  ]
}
```

---

## 6. 批量标注业务信息
### POST /api/bulk_mark
为多条扫描记录批量写入业务属性。
- JSON body：
```json
{
  "scan_ids": [1,2,3],
  "business_type": "金融",
  "department": "风控部",
  "owner": "张三",
  "classification": "机密",
  "retention_period": 365,
  "notes": "批量标注",
  "processing_advice": "阻断",
  "sensitivity_level": "高",
  "entry_time": "2025-11-06T22:00"
}
```

**响应**：`{ "success": true, "message": "成功标注 3 个文件", "count": 3 }`

---

## 7. 敏感类型与权重
### GET /api/sensitive_types
返回支持的敏感数据类型列表。

### GET /api/weights
返回当前权重与默认权重。
```json
{
  "success": true,
  "types": ["ID_CARD","BANK_CARD","PHONE","ID_CARD_IMAGE","BANK_CARD_IMAGE","CUSTOM_xxx"],
  "weights": { "ID_CARD": 0.08, "BANK_CARD": 0.07 },
  "default_weights": { "ID_CARD": 0.08, "BANK_CARD": 0.07, "PHONE": 0.05, "ID_CARD_IMAGE": null }
}
```

### POST /api/weights/save
保存单个类型的权重。
- JSON body：`{ "type": "ID_CARD", "weight": 0.1 }`

---

## 8. 扫描统计
### GET /api/scan_stats
返回扫描总数、完成/失败数及风险等级分布。
```json
{
  "total_scans": 20,
  "completed_scans": 18,
  "failed_scans": 2,
  "risk_levels": { "无": 5, "低": 8, "中": 5, "高": 2 }
}
```

---

## 9. 自动文件识别
### POST /api/upload
上传文件并自动识别（与 `/upload` 同步逻辑，落库后返回 JSON）。
- 请求：`multipart/form-data` 字段 `file`
- 流程：校验扩展名 → 文件指纹去重（重复返回 `existing_scan_id`）→ 识别 + 风险评估 + 历史入库

**成功响应**
```json
{
  "success": true,
  "scan_id": 12,
  "file_name": "demo.pdf",
  "file_size": 12345,
  "file_type": "pdf",
  "risk_level": "中",
  "sensitive_count": 2,
  "sensitive_types": "ID_CARD,BANK_CARD",
  "sensitive_items": [
    { "type": "ID_CARD", "content": "440101199001011234", "position": [10, 28], "confidence": 0.96, "level": "high", "action": "mask_data" }
  ]
}
```
重复文件：`409` + `{ "success": false, "error": "该文件已扫描", "existing_scan_id": 3 }`

---

## 10. 文本扫描
### POST /api/text_scan
复用 `/text_scan` 的检测逻辑，写入 `TextScanHistory` 并返回 JSON。
- form-data 或 JSON：
  - `text_content`* / `text`：待检测文本

**成功响应**
```json
{
  "success": true,
  "scan_id": 23,
  "text_content": "我叫张三，身份证 4401...",
  "risk_level": "高",
  "risk_assessment": { "risk_level": "高", "score": 0.92 },
  "sensitive_count": 3,
  "sensitive_types": "ID_CARD,NAME,PHONE",
  "sensitive_items": [
    { "type": "ID_CARD", "content": "4401...", "position": [18, 36], "confidence": 0.97, "level": "high", "action": "mask_data" }
  ]
}
```

---

## 11. 脱敏服务
### POST /api/masking
对文本或上传的 TXT/JSON/CSV 内容进行识别并返回脱敏结果。
- form-data：`file`（三种格式之一） 或 `text_content`
- JSON：`{ "text_content": "..." }`

**响应示例**
```json
{
  "success": true,
  "file_name": "sample.txt",
  "original_text": "张三身份证 4401...",
  "masked_text": "张*身份证 4401****1234",
  "sensitive_items": [
    { "type": "ID_CARD", "content": "4401...", "position": [6, 24], "confidence": 0.95, "level": "high", "action": "mask_data" }
  ]
}
```

---

## 12. 手工录入扫描记录
### POST /api/manual_upload
绕过识别，直接写入扫描记录及业务信息。
- form-data / JSON：
  - `file_name`*、`file_type`*；`file_size`、`file_hash` 可选
  - `file_path`：未传默认等于 `file_name`
  - `sensitive_count`、`risk_level`、`sensitive_types`：可选
  - 业务：`business_type` / `department` / `owner` / `classification` / `retention_period` / `notes` / `processing_advice` / `sensitivity_level`

**响应**
```json
{ "success": true, "scan_id": 101, "msg": "自助录入成功" }
```

---

## 13. 状态说明
- 状态码：成功返回 200；参数校验失败 400；重复资源 409；未找到 404；内部异常 500
- 文件大小与类型限制：参考 `config.ALLOWED_EXTENSIONS`
- 日志：访问日志写入 `logs/access_YYYY-MM-DD.log`
- 清理：定时清理 `uploads` 目录的临时文件
