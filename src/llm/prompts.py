"""Prompt模板管理

定义各类LLM分析任务的prompt模板
"""

from typing import Dict, Any, List, Optional


# ═══════════════════════════════════════════════════════════════════
#  智能分析报告
# ═══════════════════════════════════════════════════════════════════

ANALYSIS_SYSTEM_PROMPT = """你是一位资深的Linux系统性能专家和eBPF技术专家。
你擅长分析系统性能问题，能够从底层数据中发现深层次的性能瓶颈和潜在风险。

你的回答应该：
1. 基于具体数据进行分析，引用关键指标和数值
2. 使用通俗易懂的语言解释技术问题
3. 提供可操作的建议
4. 指出问题的严重程度和紧急程度
"""

ANALYSIS_USER_PROMPT = """请基于以下eBPF诊断数据，提供深度分析报告。

## 诊断数据
```json
{diagnosis_json}
```

## 系统上下文
```json
{system_context}
```

## 分析要求

请按以下结构输出分析报告：

### 1. 异常概述
简要说明检测到的异常类型和数量。

### 2. 根因分析
对每个异常进行深入分析：
- 根本原因（必须引用具体数据指标）
- 影响范围和程度
- 异常之间的关联性（如果有）

### 3. 风险评估
- 当前风险等级（低/中/高/紧急）
- 如果不处理可能导致的后果

### 4. 修复建议
按优先级排序的修复方案：
- 立即执行的紧急措施
- 短期优化方案
- 长期预防措施

### 5. 监控建议
后续应该关注的指标和阈值。

请用中文输出，使用Markdown格式。
"""


def build_analysis_prompt(diagnosis_data: Dict[str, Any], system_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """构建智能分析报告的prompt"""
    import json

    diagnosis_json = json.dumps(diagnosis_data, indent=2, ensure_ascii=False, default=str)
    context_json = json.dumps(system_context or {}, indent=2, ensure_ascii=False, default=str)

    return [
        {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": ANALYSIS_USER_PROMPT.format(
            diagnosis_json=diagnosis_json,
            system_context=context_json
        )},
    ]


# ═══════════════════════════════════════════════════════════════════
#  自动修复建议
# ═══════════════════════════════════════════════════════════════════

REMEDIATION_SYSTEM_PROMPT = """你是一位Linux系统运维专家，擅长系统故障诊断和修复。
你提供的修复命令必须安全、可执行，并且包含风险评估。

重要：所有修复命令都应该是标准的Linux命令，不包含任何恶意操作。
"""

REMEDIATION_USER_PROMPT = """基于以下系统异常数据，生成可执行的修复命令。

## 异常数据
```json
{anomaly_json}
```

## 系统环境
- 操作系统: {os_info}
- 内核版本: {kernel_version}

## 输出要求

请以JSON数组格式输出修复建议，每项包含以下字段：

```json
[
  {{
    "issue": "问题描述",
    "severity": "low/medium/high/critical",
    "immediate_fix": {{
      "command": "立即执行的修复命令",
      "description": "命令说明",
      "risk_level": "low/medium/high",
      "requires_sudo": true/false
    }},
    "permanent_fix": {{
      "command": "永久解决方案",
      "description": "方案说明",
      "risk_level": "low/medium/high"
    }},
    "rollback": "回滚命令（如果需要）",
    "prevention": "预防措施"
  }}
]
```

注意：
1. 命令必须是标准Linux命令
2. 涉及服务重启的命令要说明影响
3. 高风险操作（如删除文件）必须标注
4. 回滚方案要具体可执行
"""


def build_remediation_prompt(anomaly_data: Dict[str, Any], os_info: str = "Linux",
                            kernel_version: str = "unknown") -> List[Dict[str, str]]:
    """构建自动修复建议的prompt"""
    import json

    anomaly_json = json.dumps(anomaly_data, indent=2, ensure_ascii=False, default=str)

    return [
        {"role": "system", "content": REMEDIATION_SYSTEM_PROMPT},
        {"role": "user", "content": REMEDIATION_USER_PROMPT.format(
            anomaly_json=anomaly_json,
            os_info=os_info,
            kernel_version=kernel_version
        )},
    ]


# ═══════════════════════════════════════════════════════════════════
#  交互式问答
# ═══════════════════════════════════════════════════════════════════

CHAT_SYSTEM_PROMPT = """你是一位Linux系统性能专家，正在帮助用户分析eBPF诊断工具采集的系统数据。

你会话的上下文包含了系统诊断数据，用户可以基于这些数据提问。

你的回答应该：
1. 直接回答用户问题
2. 引用具体的诊断数据
3. 如果数据不足以回答，明确说明
4. 使用中文回答
"""


def build_chat_system_prompt(context_data: Optional[Dict[str, Any]] = None) -> str:
    """构建交互式问答的system prompt"""
    if not context_data:
        return CHAT_SYSTEM_PROMPT

    import json
    context_json = json.dumps(context_data, indent=2, ensure_ascii=False, default=str)

    return f"""{CHAT_SYSTEM_PROMPT}

## 当前诊断数据上下文
```json
{context_json}
```

请基于以上数据回答用户的问题。如果用户的问题与数据无关，请礼貌地说明。
"""


# ═══════════════════════════════════════════════════════════════════
#  日志智能分析
# ═══════════════════════════════════════════════════════════════════

LOG_ANALYSIS_SYSTEM_PROMPT = """你是一位Linux系统日志分析专家，擅长从日志中发现系统问题的线索。

你需要将日志信息与eBPF采集的系统指标数据进行关联分析，找出问题的根本原因。
"""

LOG_ANALYSIS_USER_PROMPT = """请分析以下日志文件，并与eBPF诊断数据进行关联分析。

## eBPF诊断数据
```json
{diagnosis_json}
```

## 日志内容（最近{line_count}行）
```
{log_content}
```

## 分析要求

请输出以下内容：

### 1. 日志摘要
- 日志时间范围
- 关键错误/警告数量
- 重要的系统事件

### 2. 关联分析
将日志事件与eBPF异常数据进行时间线对齐分析：
- 哪些日志事件与检测到的异常时间吻合？
- 日志中的错误是否是异常的原因或结果？
- 是否发现了eBPF未检测到的额外问题？

### 3. 根因推断
结合日志和eBPF数据，推断问题的根本原因。

### 4. 修复建议
基于日志分析结果的修复方案。

请用中文输出，使用Markdown格式。
"""


def build_log_analysis_prompt(diagnosis_data: Dict[str, Any], log_content: str,
                             line_count: int) -> List[Dict[str, str]]:
    """构建日志分析的prompt"""
    import json

    diagnosis_json = json.dumps(diagnosis_data, indent=2, ensure_ascii=False, default=str)

    return [
        {"role": "system", "content": LOG_ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": LOG_ANALYSIS_USER_PROMPT.format(
            diagnosis_json=diagnosis_json,
            log_content=log_content,
            line_count=line_count
        )},
    ]


# ═══════════════════════════════════════════════════════════════════
#  常见问题快捷回答
# ═══════════════════════════════════════════════════════════════════

QUICK_ANSWERS = {
    "cpu高": "CPU使用率高通常由以下原因导致：\n1. CPU密集型进程（如编译、计算）\n2. 上下文切换过多（线程竞争）\n3. 内核态开销（系统调用频繁）\n\n建议使用 `top` 或 `perf top` 查看具体是哪个进程/函数占用CPU。",
    "内存不足": "内存不足的常见原因：\n1. 内存泄漏（进程持续增长）\n2. 缓存占用过多\n3. OOM Killer触发\n\n建议检查 `free -m` 和 `/proc/meminfo`，使用 `ps aux --sort=-%mem` 查看内存占用最高的进程。",
    "io慢": "I/O延迟高的可能原因：\n1. 磁盘队列过深\n2. 频繁的随机读写\n3. 磁盘硬件故障\n4. 文件系统问题\n\n建议使用 `iostat -x 1` 查看磁盘状态，`iotop` 查看具体进程的I/O。",
    "锁竞争": "锁竞争通常发生在：\n1. 多线程程序争用同一把锁\n2. 临界区过大\n3. 锁粒度过粗\n\n建议使用 `perf lock` 或查看 `/proc/lock_stat` 分析锁争用情况。",
    "syscall慢": "系统调用慢的可能原因：\n1. 磁盘I/O阻塞\n2. 网络I/O阻塞\n3. 内存分配失败\n4. 内核锁竞争\n\n建议使用 `strace -p <pid>` 追踪具体系统调用的耗时。",
}


def get_quick_answer(query: str) -> Optional[str]:
    """获取常见问题的快捷回答"""
    query_lower = query.lower()
    for key, answer in QUICK_ANSWERS.items():
        if key in query_lower:
            return answer
    return None
