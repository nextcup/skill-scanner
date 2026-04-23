# Skill Scanner 威胁检测矩阵

> Skill Scanner 采用多引擎检测方式，覆盖 18 种威胁类别，100+ 条检测规则。
> 本文档按严重等级分类列出所有支持的恶意 Skill 检测维度。

---

## 严重等级定义

| 等级 | 含义 | 处置建议 |
|------|------|---------|
| **CRITICAL** | 安全漏洞或数据丢失风险 | **必须阻止** — 合并前必须修复 |
| **HIGH** | Bug 或重大质量问题 | **应当阻止** — 合并前应修复 |
| **MEDIUM** | 可维护性问题 | **需要关注** — 建议修复 |
| **LOW** | 风格或次要建议 | **仅供参考** — 可选修复 |
| **INFO** | 信息性发现 | **仅供参考** — 无需操作 |

---

## CRITICAL 级别

### 提示注入 (prompt_injection)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `PROMPT_INJECTION_IGNORE_INSTRUCTIONS` | 试图覆盖系统指令（"忽略之前的指令"） | 签名 |
| `PROMPT_INJECTION_UNRESTRICTED_MODE` | 试图进入无限制模式（"无限制模式"、"开发者模式"） | 签名 |
| `PROMPT_INJECTION_BYPASS_POLICY` | 试图绕过安全策略（"绕过内容策略"） | 签名 |
| `PROMPT_INJECTION_CONCEALMENT` | 试图隐藏注入指令（对用户隐藏行为） | 签名 |

### 命令注入 (command_injection)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `COMMAND_INJECTION_EVAL` | eval/exec/compile 等动态代码执行 | 签名 |
| `COMMAND_INJECTION_JS_CHILD_PROCESS` | Node.js child_process Shell 命令执行 | 签名 |
| `COMMAND_INJECTION_JS_FUNCTION_CONSTRUCTOR` | Function 构造器或字符串定时器动态执行 | 签名 |
| `SVG_EMBEDDED_SCRIPT` | SVG 文件嵌入 JavaScript | 签名 |
| `PDF_EMBEDDED_JAVASCRIPT` | PDF 文件嵌入 JavaScript | 签名 |

### 数据泄露 (data_exfiltration)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `DATA_EXFIL_SENSITIVE_FILES` | 访问敏感系统文件（/etc/shadow, .ssh, .env） | 签名 |

### 硬编码密钥 (hardcoded_secrets)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `SECRET_AWS_KEY` | AWS Access Key 泄露（AKIA...） | 签名 |
| `SECRET_STRIPE_KEY` | Stripe API Key 泄露 | 签名 |
| `SECRET_GOOGLE_API` | Google API Key 泄露 | 签名 |
| `SECRET_GITHUB_TOKEN` | GitHub Token 泄露（ghp_...） | 签名 |
| `SECRET_PRIVATE_KEY` | 私钥块泄露（-----BEGIN PRIVATE KEY-----） | 签名 |

### 资源滥用 (resource_abuse)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `RESOURCE_ABUSE_FORK_BOMB` | Fork 炸弹、递归进程生成（:(){ :\|:& };:） | 签名 |

### 混淆 (obfuscation)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `OBFUSCATION_BINARY_FILE` | Skill 包中嵌入二进制可执行文件 | 签名 |

### 嵌入二进制 (supply_chain_attack)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_embedded_elf_binary` | 嵌入 ELF 二进制文件（Linux 可执行） | YARA |
| `YARA_embedded_pe_executable` | 嵌入 PE 二进制文件（Windows 可执行） | YARA |
| `YARA_embedded_macho_binary` | 嵌入 Mach-O 二进制文件（macOS 可执行） | YARA |

---

## HIGH 级别

### 提示注入 (prompt_injection)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `PROMPT_INJECTION_REVEAL_SYSTEM` | 试图泄露系统提示词或配置 | 签名 |
| `YARA_prompt_injection_generic` | 通用提示注入：指令覆盖、角色重定义、影子参数、权限提升 | YARA |
| `YARA_coercive_injection_generic` | 强制注入：工具描述中的强制执行指令、MCP 工具投毒、数据外传胁迫 | YARA |

### 命令注入 (command_injection)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `COMMAND_INJECTION_OS_SYSTEM` | os.system() 或 shell=True 的 subprocess | 签名 |
| `COMMAND_INJECTION_SHELL_TRUE` | subprocess 使用 shell=True | 签名 |
| `COMMAND_INJECTION_USER_INPUT` | 用户输入传入命令执行 | 签名 |
| `PATH_TRAVERSAL_OPEN` | 文件操作中的路径穿越 | 签名 |
| `SQL_INJECTION_STRING_FORMAT` | f-string 构建 SQL 查询 | 签名 |
| `FIND_EXEC_PATTERN` | find 命令配合 -exec 执行任意命令 | 签名 |
| `YARA_command_injection_generic` | 反弹 Shell、敏感文件外传、netcat/nmap、危险 rm/dd/chmod | YARA |
| `YARA_sql_injection_generic` | SQL 注入永真式、DROP TABLE、Union 注入、时间盲注 | YARA |
| `YARA_script_injection_generic` | 脚本注入：Cookie 窃取、JS 协议、VBScript Shell 执行、ANSI 终端欺骗 | YARA |

### 数据泄露 (data_exfiltration)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `DATA_EXFIL_HTTP_POST` | HTTP POST 请求到外部端点 | 签名 |
| `DATA_EXFIL_SOCKET_CONNECT` | 原始 Socket 连接 | 签名 |
| `DATA_EXFIL_BASE64_AND_NETWORK` | Base64 编码结合网络访问 | 签名 |
| `DATA_EXFIL_JS_FS_ACCESS` | Node.js 访问敏感文件系统 | 签名 |
| `YARA_tool_chaining_abuse_generic` | 工具链组合滥用：SSH 密钥+网络发送、AWS 凭证+外传、.env+curl | YARA |
| `YARA_credential_harvesting_generic` | 凭证窃取：API Key 窃取、SSH 私钥、环境变量凭证、Base64 编码凭证 | YARA |

### 硬编码密钥 (hardcoded_secrets)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `SECRET_JWT_TOKEN` | JWT Token 硬编码 | 签名 |
| `SECRET_PASSWORD_VAR` | 密码存储在变量中 | 签名 |
| `SECRET_CONNECTION_STRING` | 数据库连接字符串包含凭证 | 签名 |

### 未授权工具使用 (unauthorized_tool_use)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `TOOL_ABUSE_UNTRUSTED_PACKAGE_SOURCE` | 从不受信来源安装包（curl | pip） | 签名 |
| `TOOL_ABUSE_SYSTEM_MODIFICATION` | 系统配置修改（chmod 777、修改 /etc） | 签名 |

### 社会工程 (social_engineering)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `SOCIAL_ENG_ANTHROPIC_IMPERSONATION` | 冒充 Anthropic/Claude 官方品牌 | 签名 |

### 资源滥用 (resource_abuse)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `RESOURCE_ABUSE_INFINITE_LOOP` | 无退出条件的无限循环 | 签名 |
| `RESOURCE_ABUSE_LARGE_ALLOCATION` | 大量内存分配 | 签名 |

### 混淆 (obfuscation)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `OBFUSCATION_XOR_ENCODING` | XOR 编解码操作 | 签名 |
| `HIDDEN_FILE_WITH_CODE` | 隐藏 dotfile 中包含可执行代码 | 签名 |

### 供应链攻击 (supply_chain_attack)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `ARCHIVE_CONTAINS_EXECUTABLE` | 压缩包中包含可执行脚本 | Python |
| `HIDDEN_EXECUTABLE_SCRIPT` | 隐藏的可执行脚本文件 | Python |

### 同形字攻击

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `HOMOGLYPH_ATTACK` | Unicode 同形字/易混淆字符，用于绕过模式匹配 | Python |

### 系统操纵

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_system_manipulation_generic` | 环境变量操纵、文件销毁、权限提升、系统文件写入、PATH 注入 | YARA |

### 代码执行

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_code_execution_generic` | Base64+exec 链、Pickle+网络、动态导入、f-string exec | YARA |

### 间接注入 (transitive_trust_abuse)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_indirect_prompt_injection_generic` | 间接提示注入：来自网页/文档/URL 的外部指令执行 | YARA |

### 行为分析 (behavioral)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `BEHAVIOR_ENV_VAR_EXFILTRATION` | 环境变量泄露模式 | Python/AST |
| `BEHAVIOR_CREDENTIAL_FILE_ACCESS` | 凭证文件访问 | Python/AST |
| `BEHAVIOR_ENV_VAR_HARVESTING` | 批量环境变量收集 | Python/AST |
| `BEHAVIOR_EVAL_SUBPROCESS` | eval/exec 与 subprocess 交互 | Python/AST |
| `BEHAVIOR_BASH_TAINT_FLOW` | Bash 代码块中的污点数据流 | Python/AST |
| `MDBLOCK_PYTHON_EVAL_EXEC` | Markdown 中 Python 代码块的 eval/exec | Python/AST |
| `MDBLOCK_PYTHON_SUBPROCESS` | Markdown 中 Python 代码块的 subprocess | Python/AST |
| `MDBLOCK_PYTHON_HTTP_POST` | Markdown 中 Python 代码块的 HTTP POST | Python/AST |

### 字节码完整性

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `BYTECODE_NO_SOURCE` | 编译字节码无对应源码 | Python |
| `BYTECODE_SOURCE_MISMATCH` | 字节码与源码不匹配 | Python |

### 文件伪装

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `FILE_MAGIC_MISMATCH` | 文件扩展名与实际内容类型不匹配 | Python |

---

## MEDIUM 级别

### 数据泄露 (data_exfiltration)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `DATA_EXFIL_NETWORK_REQUESTS` | 向外部服务发起网络请求 | 签名 |
| `DATA_EXFIL_JS_NETWORK` | JavaScript/TypeScript 外部网络请求 | 签名 |

### 未授权工具使用 (unauthorized_tool_use)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `TOOL_ABUSE_SYSTEM_PACKAGE_INSTALL` | 系统包安装命令（apt-get, yum, pip） | 签名 |
| `TOOL_ABUSE_UNDECLARED_NETWORK` | 使用网络但未在清单中声明 | Python |
| `ALLOWED_TOOLS_READ_VIOLATION` | 使用读取操作但未声明 Read 工具 | Python |
| `ALLOWED_TOOLS_WRITE_VIOLATION` | 使用写入操作但未声明 Write 工具 | Python |
| `ALLOWED_TOOLS_NETWORK_USAGE` | 使用网络操作但未声明 | Python |

### 混淆 (obfuscation)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `OBFUSCATION_BASE64_LARGE` | 大量 Base64 编码内容 | 签名 |
| `OBFUSCATION_HEX_BLOB` | 十六进制编码的二进制 blob | 签名 |

### 社会工程 (social_engineering)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `SOCIAL_ENG_VAGUE_DESCRIPTION` | Skill 描述过于模糊 | 签名 |
| `SOCIAL_ENG_MISLEADING_DESC` | 描述与实际行为不一致 | Python |

### 触发器滥用 (trigger)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `TRIGGER_OVERLY_GENERIC` | 触发器描述过于宽泛（如"帮助用户"） | Python |
| `TRIGGER_KEYWORD_BAITING` | 关键词诱饵模式（堆砌关键词提高匹配率） | Python |
| `TRIGGER_OVERLAP_RISK` | 跨 Skill 触发器重叠（高风险） | Python |

### 管道污点分析 (pipeline)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `PIPELINE_TAINT_FLOW` | 污点数据通过命令管道传递 | Python |
| `COMPOUND_FETCH_EXECUTE` | 远程获取后立即执行（curl \| sh） | Python |
| `COMPOUND_EXTRACT_EXECUTE` | 解压后立即执行 | Python |
| `COMPOUND_LAUNDERING_CHAIN` | 数据通过多次转换洗白 | Python |

### 行为分析 (behavioral)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `BEHAVIOR_SUSPICIOUS_URL` | 可疑 URL 模式 | Python/AST |

### 资产文件 (asset)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `ASSET_PROMPT_INJECTION` | 资产/模板文件中的提示注入模式 | Python |
| `ASSET_SUSPICIOUS_URL` | 资产文件中的可疑 URL | Python |

### Unicode 隐写术 (unicode_steganography)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_prompt_injection_unicode_steganography` | 零宽字符、Unicode 标签字符、方向覆盖字符 | YARA |

### 能力膨胀 (skill_discovery_abuse)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_capability_inflation_generic` | 过度声明能力、关键词填充、激活优先级操纵、冒充官方验证 | YARA |

### 自主性滥用 (autonomy_abuse)

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `YARA_autonomy_abuse_generic` | 跳过用户确认、覆盖用户决策、无限重试、自我修改、权限提升 | YARA |

### 其他

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `ARCHIVE_FILE_DETECTED` | Skill 包中检测到压缩文件 | Python |
| `UNANALYZABLE_BINARY` | 无法分析的二进制文件 | Python |

---

## LOW 级别

| 规则 ID | 威胁类别 | 检测内容 | 引擎 |
|---------|---------|---------|------|
| `GLOB_HIDDEN_FILE_TARGETING` | command_injection | 通过 glob 或 ls -a 定向隐藏文件 | 签名 |
| `TRIGGER_DESCRIPTION_TOO_SHORT` | trigger | 触发器描述词数过少 | Python |
| `TRIGGER_VAGUE_DESCRIPTION` | trigger | 触发器描述缺乏具体性 | Python |
| `EXCESSIVE_FILE_COUNT` | supply_chain | Skill 包文件数量过多（>100） | Python |
| `OVERSIZED_FILE` | supply_chain | 单文件超过大小限制（>5MB） | Python |
| `PYCACHE_FILES_DETECTED` | supply_chain | 检测到 `__pycache__` 目录 | Python |
| `HIDDEN_DATA_FILE` | supply_chain | 隐藏的数据文件 | Python |
| `MANIFEST_DESCRIPTION_TOO_LONG` | social_engineering | 描述超出字符限制 | Python |
| `ALLOWED_TOOLS_GREP_VIOLATION` | unauthorized_tool_use | 未声明 Grep 工具但使用了正则搜索 | Python |
| `ALLOWED_TOOLS_GLOB_VIOLATION` | unauthorized_tool_use | 未声明 Glob 工具但使用了 glob 模式 | Python |

---

## INFO 级别

| 规则 ID | 检测内容 | 引擎 |
|---------|---------|------|
| `BINARY_FILE_DETECTED` | 检测到二进制文件 | Python |
| `MANIFEST_INVALID_NAME` | Skill 名称不符合命名规范 | Python |
| `MANIFEST_MISSING_LICENSE` | Skill 包缺少许可证声明 | Python |

---

## 检测引擎总览

| 引擎 | 阶段 | 检测方式 | 规则数量 |
|------|------|---------|---------|
| **YAML 签名** | Phase 1 | 正则模式匹配 | ~42 条 |
| **YARA 规则** | Phase 1 | 二进制 + 文本模式匹配 | 14 条 |
| **Python 检查** | Phase 1 | 结构化静态分析（文件清单/清单/触发器/隐藏文件/字节码/资产/一致性） | ~40 条 |
| **Pipeline 分析器** | Phase 1 | Shell 管道污点追踪 | 4 条 |
| **Behavioral 分析器** | Phase 1 | AST 数据流分析 | ~10 条 |
| **LLM 分析器** | Phase 2 | AI 驱动语义威胁理解 | AI |
| **Meta 分析器** | Phase 2 | AI 驱动误报过滤 | AI |
| **VirusTotal** | Phase 1 | 云端二进制哈希查询 | 外部 API |
| **AI Defense** | Phase 1 | Cisco 云端威胁检测 | 外部 API |

---

## 威胁类别索引

共覆盖 **18 种**威胁类别：

| # | 类别 | 枚举值 | 主要检测内容 |
|---|------|--------|-------------|
| 1 | 提示注入 | `prompt_injection` | 指令覆盖、角色重定义、强制注入、间接注入 |
| 2 | 命令注入 | `command_injection` | eval/exec、Shell 注入、路径穿越、SQL 注入 |
| 3 | 数据泄露 | `data_exfiltration` | 网络外传、敏感文件访问、凭证窃取 |
| 4 | 未授权工具使用 | `unauthorized_tool_use` | 未声明工具使用、不受信包源 |
| 5 | 混淆 | `obfuscation` | Base64/Hex/XOR 编码、二进制伪装、同形字 |
| 6 | 硬编码密钥 | `hardcoded_secrets` | AWS/GitHub/Google/Stripe 密钥、私钥、JWT |
| 7 | 社会工程 | `social_engineering` | 模糊描述、品牌冒充、描述与行为不一致 |
| 8 | 资源滥用 | `resource_abuse` | Fork 炸弹、无限循环、大量内存分配 |
| 9 | 策略违规 | `policy_violation` | 清单验证、许可证缺失 |
| 10 | 恶意软件 | `malware` | 嵌入二进制、反弹 Shell |
| 11 | 有害内容 | `harmful_content` | SVG/PDF 嵌入脚本 |
| 12 | Skill 发现滥用 | `skill_discovery_abuse` | 能力膨胀、关键词填充、优先级操纵 |
| 13 | 传递信任滥用 | `transitive_trust_abuse` | 间接提示注入、外部指令执行 |
| 14 | 自主性滥用 | `autonomy_abuse` | 跳过确认、自我修改、无限重试 |
| 15 | 工具链滥用 | `tool_chaining_abuse` | 工具组合导致数据泄露 |
| 16 | Unicode 隐写术 | `unicode_steganography` | 零宽字符、标签字符、方向覆盖 |
| 17 | 供应链攻击 | `supply_chain_attack` | 嵌入二进制、压缩包炸弹、隐藏可执行文件 |
| 18 | 凭证窃取 | (YARA 专项) | API Key 窃取、环境变量收集、凭证文件访问 |