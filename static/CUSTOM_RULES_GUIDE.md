# 自定义敏感信息规则使用说明

## 功能概述

自定义敏感信息规则功能允许用户通过文本输入或文件上传的方式添加自定义的敏感信息识别规则，扩展系统的敏感信息识别能力。

## 支持的格式

### 1. JSON格式
```json
[
    {
        "name": "自定义银行卡号",
        "description": "识别特定格式的银行卡号",
        "pattern": "\\b6\\d{15}\\b",
        "sensitivity_level": "high",
        "action_type": "mask_data",
        "threshold": 0.9,
        "masking_pattern": "****{content[-4:]}",
        "test_samples": [
            {
                "text": "6222021234567890",
                "expected_match": true,
                "sample_type": "positive"
            }
        ]
    }
]
```

### 2. YAML格式
```yaml
- name: 自定义身份证号
  description: 识别特定地区的身份证号
  pattern: "\\b110101\\d{12}\\b"
  sensitivity_level: high
  action_type: mask_data
  threshold: 0.95
  masking_pattern: "{content[:4]}********{content[-4:]}"
  test_samples:
    - text: "110101199001011234"
      expected_match: true
      sample_type: positive
```

### 3. 文本格式
```
# 自定义敏感信息规则
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
name: 自定义邮箱
description: 识别特定域名的邮箱
pattern: "\\b[A-Za-z0-9._%+-]+@company\\.com\\b"
sensitivity_level: medium
action_type: mask_data
threshold: 0.85
masking_pattern: "{content.split('@')[0][0]}***@{content.split('@')[1]}"
test_samples: [{"text": "user@company.com", "expected_match": true, "sample_type": "positive"}]
```

## 字段说明

| 字段名 | 类型 | 必需 | 说明 |
|--------|------|------|------|
| name | string | 是 | 规则名称，用于标识规则 |
| description | string | 否 | 规则描述，说明规则的用途 |
| pattern | string | 是 | 正则表达式模式，定义匹配规则 |
| sensitivity_level | string | 是 | 敏感级别：low/medium/high/critical |
| action_type | string | 是 | 处置建议：log_only/mask_data/block_access/delete_data/notify_admin |
| threshold | float | 否 | 识别阈值，范围0.0-1.0，默认0.8 |
| masking_pattern | string | 否 | 脱敏模式，使用{content}占位符 |
| test_samples | array | 否 | 测试样本，用于验证规则 |

## 使用步骤

### 1. 访问自定义规则页面
- 在系统导航栏中点击"自定义规则"
- 或直接访问 `/custom_rules` 页面

### 2. 添加单个规则
- 点击"添加规则"按钮
- 填写规则信息：
  - 规则名称：给规则起一个有意义的名字
  - 规则描述：说明规则的用途
  - 正则表达式：定义匹配模式
  - 敏感级别：选择适当的风险等级
  - 处置建议：选择处理方式
  - 识别阈值：设置置信度阈值
  - 脱敏模式：定义脱敏方式（可选）

### 3. 批量导入规则
- 切换到"批量导入"选项卡
- 选择格式类型（JSON/YAML/文本）
- 在文本框中粘贴规则内容
- 点击"导入规则"按钮
- 系统会验证规则格式并导入有效规则

### 4. 测试规则
- 切换到"规则测试"选项卡
- 输入测试文本
- 输入要测试的规则内容
- 选择格式类型
- 点击"开始测试"查看匹配结果

### 5. 管理规则
- 在规则列表中查看所有规则
- 可以启用/禁用规则
- 可以删除不需要的规则
- 查看规则的详细信息

## 正则表达式示例

### 银行卡号
```regex
\\b6\\d{15}\\b          # 以6开头的16位数字
\\b4\\d{15}\\b          # 以4开头的16位数字（Visa）
\\b5[1-5]\\d{14}\\b     # 以51-55开头的16位数字（MasterCard）
```

### 身份证号
```regex
\\b110101\\d{12}\\b     # 北京朝阳区身份证号
\\b\\d{17}[\\dXx]\\b    # 18位身份证号
```

### 手机号
```regex
\\b138\\d{8}\\b         # 138开头的手机号
\\b1[3-9]\\d{9}\\b      # 中国大陆手机号
```

### 邮箱
```regex
\\b[A-Za-z0-9._%+-]+@company\\.com\\b    # 公司邮箱
\\b[A-Za-z0-9._%+-]+@gmail\\.com\\b     # Gmail邮箱
```

### IP地址
```regex
\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b    # 内网IP
\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b  # 10.x.x.x网段
```

## 脱敏模式示例

### 银行卡号脱敏
```
****{content[-4:]}                    # 显示后4位
{content[:4]}****{content[-4:]}       # 显示前4位和后4位
```

### 身份证号脱敏
```
{content[:4]}********{content[-4:]}   # 显示前4位和后4位
{content[:6]}****{content[-4:]}       # 显示前6位和后4位
```

### 手机号脱敏
```
{content[:3]}****{content[-4:]}       # 显示前3位和后4位
{content[:3]}****{content[-2:]}       # 显示前3位和后2位
```

### 邮箱脱敏
```
{content.split('@')[0][0]}***@{content.split('@')[1]}  # 用户名首字符+***+域名
***@{content.split('@')[1]}                            # ***+域名
```

## 注意事项

1. **正则表达式语法**：使用Python正则表达式语法，注意转义字符
2. **脱敏模式**：必须包含{content}占位符，可以使用Python字符串切片语法
3. **测试样本**：建议提供正样本和负样本，帮助验证规则准确性
4. **性能考虑**：复杂的正则表达式可能影响扫描性能
5. **规则冲突**：多个规则可能匹配同一内容，系统会按优先级处理

## 常见问题

### Q: 正则表达式怎么写？
A: 使用Python正则表达式语法，可以参考示例或在线正则表达式测试工具。

### Q: 脱敏模式不生效？
A: 检查脱敏模式是否包含{content}占位符，语法是否正确。

### Q: 规则导入失败？
A: 检查JSON/YAML格式是否正确，必需字段是否完整。

### Q: 如何测试规则？
A: 使用"规则测试"功能，输入测试文本和规则内容进行验证。

### Q: 规则可以修改吗？
A: 目前不支持修改，可以删除后重新添加。

## 最佳实践

1. **规则命名**：使用有意义的名称，便于管理
2. **描述详细**：提供清晰的规则描述
3. **测试充分**：提供足够的测试样本
4. **阈值合理**：根据实际情况设置识别阈值
5. **定期审查**：定期检查规则的有效性和准确性
