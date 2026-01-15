import argparse
import pathlib
import re
import os
import json
import concurrent.futures
from datetime import datetime

def is_shell_script(file_path):
    path = pathlib.Path(file_path)

    # 1. 基础检查
    if not path.is_file() or path.stat().st_size == 0:
        return False
    if path.stat().st_size > 10 * 1024 * 1024:
        return False

    # 2. 后缀检查
    shell_extensions = {'.sh', '.bash', '.zsh', '.ksh'}
    if path.suffix.lower() in shell_extensions:
        return True

    # 3. Shebang 内容检查
    try:
        with open(file_path, 'rb') as f:
            first_line = f.readline(32).decode('utf-8-sig', errors='ignore').strip()
            if first_line.startswith('#!'):
                interpreters = ['sh', 'bash', 'zsh', 'ash', 'dash']
                if any(interp in first_line for interp in interpreters):
                    return True
    except PermissionError:
        # 特别针对读取内容时的权限问题进行打印
        print(f"[-] Permission denied while reading: {file_path}")
        return False
    except Exception as e:
        # 其他错误（如文件被占用等）则静默跳过
        return False

    return False


def get_all_shell_files(root_dir):
    """
    递归遍历目录，返回所有 shell 脚本的路径
    遇到权限不足时打印提示并跳过
    """
    target_files = []
    base_path = pathlib.Path(root_dir)

    # 使用 os.walk 能更精确地控制目录进入权限
    for root, dirs, files in os.walk(root_dir):
        # 检查当前目录是否可读
        if not os.access(root, os.R_OK):
            print(f"[-] Permission denied (Directory): {root}")
            continue

        for file in files:
            file_path = pathlib.Path(root) / file
            try:
                # 检查单个文件是否可读
                if not os.access(file_path, os.R_OK):
                    print(f"[-] Permission denied (File): {file_path}")
                    continue

                if is_shell_script(file_path):
                    target_files.append(str(file_path))
            except Exception as e:
                print(f"[-] Error accessing {file_path}: {e}")
                continue

    return target_files


def get_logical_lines(file_path):
    """
    预处理脚本：过滤注释，合并多行连接符，保留行号。
    返回格式: [{"line_no": int, "content": str, "raw": str}, ...]
    """
    logical_lines = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Read error: {e}")
        return []

    temp_content = ""
    start_line_no = 0
    raw_block = ""

    for i, line in enumerate(lines, 1):
        # 记录逻辑行的起始行号
        if not temp_content:
            start_line_no = i

        # 1. 处理注释：去掉每行第一个 # 及其后面的内容
        # 简单的正则：匹配不在引号内的 # 比较复杂，这里先用基础处理
        # 进阶建议：clean_line = re.sub(r'(^|\s)#.*$', '', line)
        clean_line = re.sub(r'#.*$', '', line).strip()

        raw_block += line

        # 2. 处理多行连接符 \
        if clean_line.endswith('\\'):
            # 去掉末尾的反斜杠，累加内容，继续看下一行
            temp_content += clean_line.rstrip('\\').strip() + " "
        else:
            # 当前行结束，合并完整内容
            temp_content += clean_line

            # 如果这一行不是空的（过滤掉纯注释行或空行）
            if temp_content.strip():
                logical_lines.append({
                    "line_no": start_line_no,
                    "content": temp_content.strip(),
                    "raw": raw_block.strip()
                })

            # 重置中间变量
            temp_content = ""
            raw_block = ""

    return logical_lines


def check_command_injection(logical_lines):
    findings = []

    # 定义复合规则库
    # key: 规则描述, pattern: 正则, severity: 风险等级
    injection_rules = [
        {
            "id": "DIRECT_VAR_EXEC",
            "desc": "变量直接作为命令执行 (Potential Command Injection)",
            "pattern": r"(?:^|[;&|])\s*\$(?:[a-zA-Z0-9_{}]+|[1-9*@])",
            "level": "High"
        },
        {
            "id": "WRAPPER_EXEC",
            "desc": "使用包装器执行动态内容 (eval/exec/bash -c)",
            "pattern": r"(?:^|[;&|])\s*\b(?:/[\w./]+)?(eval|exec|source|sh|bash|zsh)\b\s+.*\$",
            "level": "High"
        },
        {
            "id": "BACKTICK_EXEC",
            "desc": "在反引号或子shell中执行变量",
            "pattern": r"(`\$.*?`|\$\(\s*\$.*?\))",
            "level": "Medium"
        },
        {
            "id": "DOT_SOURCE_EXEC",
            "desc": "使用 '.' 缩写执行动态脚本",
            "pattern": r"^\s*\.\s+\$",
            "level": "Medium"
        },
        {
            "id": "PIPE_TO_SHELL",
            "desc": "通过管道将变量内容传递给Shell执行",
            "pattern": r"\|\s*(?:[\w./]*/)?\b(sh|bash|zsh|eval)\b",
            "level": "High"
        }
    ]

    for item in logical_lines:
        content = item['content']
        for rule in injection_rules:
            m = re.search(rule['pattern'], content)  # 捕获 match 对象
            if m:
                findings.append({
                    "line": item['line_no'],
                    "code": content,
                    "matched": m.group(0).strip(),  # 新增：捕获内容
                    "rule_id": rule['id'],
                    "description": rule['desc'],
                    "level": rule['level']
                })
    return findings


def check_argument_injection(logical_lines):
    findings = []

    # 定义规则库：包含严格模式(High)和通用模式(Low)
    arg_injection_rules = [
        # --- FIND ---
        {"id": "FIND_EXEC_STRICT", "level": "High", "pattern": r"find\s+.*-(exec|ok|execdir)\b.*\$",
         "desc": "find 关键参数(-exec等)包含动态变量，极高注入风险"},
        {"id": "FIND_DYNAMIC_GENERIC", "level": "Low", "pattern": r"find\s+.*\$",
         "desc": "find 包含动态参数，需人工确认变量来源是否可信"},

        # --- XARGS ---
        {"id": "XARGS_SHELL_STRICT", "level": "High", "pattern": r"xargs\s+.*(sh|bash|zsh|eval|python|perl)\b.*\$",
         "desc": "xargs 将内容传递给解释器处理且包含变量"},
        {"id": "XARGS_DYNAMIC_GENERIC", "level": "Low", "pattern": r"xargs\s+.*\$",
         "desc": "xargs 涉及动态变量，可能存在参数注入"},

        # --- TCPDUMP ---
        {"id": "TCPDUMP_Z_STRICT", "level": "High", "pattern": r"tcpdump\s+.*-z\s+\$",
         "desc": "tcpdump 使用 -z 执行动态脚本，极高风险"},
        {"id": "TCPDUMP_DYNAMIC_GENERIC", "level": "Low", "pattern": r"tcpdump\s+.*\$",
         "desc": "tcpdump 命令包含动态变量"},

        # --- SSH ---
        {"id": "SSH_PROXY_STRICT", "level": "High", "pattern": r"ssh\s+.*-o\s+ProxyCommand=.*\$",
         "desc": "ssh ProxyCommand 包含动态变量，可导致命令执行"},
        {"id": "SSH_DYNAMIC_GENERIC", "level": "Low", "pattern": r"ssh\s+.*\$", "desc": "ssh 目标或命令包含动态变量"},

        # --- TAR ---
        {"id": "TAR_CHECKPOINT_STRICT", "level": "High", "pattern": r"tar\s+.*--checkpoint-action\s*=.*\$",
         "desc": "tar 通过 checkpoint 机制执行动态命令"},
        {"id": "TAR_DYNAMIC_GENERIC", "level": "Low", "pattern": r"tar\s+.*\$",
         "desc": "tar 备份路径或参数包含动态变量"},

        # --- CURL / WGET ---
        {"id": "CURL_CONFIG_STRICT", "level": "High", "pattern": r"curl\s+.*-[K]\s+\$",
         "desc": "curl 从变量指定的文件读取配置，可能导致敏感信息泄露"},
        {"id": "NETWORK_DYNAMIC_GENERIC", "level": "Low", "pattern": r"(curl|wget)\s+.*\$",
         "desc": "网络请求工具包含动态参数"},
        # --- KERNEL MODULE LOADING ---
        {
            "id": "KMOD_DYNAMIC_INJECTION",
            "level": "High",
            "pattern": r"(?:^|[;&|])\s*(?:[\w./]*/)?(?:insmod|modprobe)\s+.*\$",
            "desc": "内核模块加载命令包含动态变量，可能导致内核级劫持"
        },
    ]

    for item in logical_lines:
        content = item['content']
        matched_this_line = False

        # 匹配策略：如果匹配到了 High，就不再报告该行的 Low 规则，减少冗余
        # 先按 High 规则过滤
        for rule in [r for r in arg_injection_rules if r['level'] == "High"]:
            m = re.search(rule['pattern'], content, re.IGNORECASE)
            if m:
                findings.append({
                    "line": item['line_no'],
                    "code": content,
                    "matched": m.group(0).strip(),  # 新增
                    "rule_id": rule['id'],
                    "level": rule['level'],
                    "description": rule['desc']
                })
                matched_this_line = True
                break

            # 如果没有命中高危，则尝试匹配低危
        if not matched_this_line:
            for rule in [r for r in arg_injection_rules if r['level'] == "Low"]:
                m = re.search(rule['pattern'], content, re.IGNORECASE)
                if m:
                    findings.append({
                        "line": item['line_no'],
                        "code": content,
                        "matched": m.group(0).strip(),  # 新增
                        "rule_id": rule['id'],
                        "level": rule['level'],
                        "description": rule['desc']
                    })
                    break

    return findings




def build_sensitive_regex(file_list):
    """
    智能构建正则：区分纯文件名、路径片段和目录。
    """
    if not file_list:
        return r"(?!x)x"

    path_patterns = []
    name_patterns = []

    for item in file_list:
        item = item.strip()
        if not item: continue

        # 统一路径分隔符
        normalized_item = item.replace('\\', '/')

        if '/' in normalized_item:
            # 针对路径或目录：直接匹配该片段，不加 \b 边界，因为路径前可能有 / 或 $变量
            path_patterns.append(re.escape(normalized_item))
        else:
            # 针对纯文件名：添加 \b 边界保护，防止 'sn' 匹配到 'snmpd'
            name_patterns.append(rf"\b{re.escape(normalized_item)}\b")

    # 合并为非捕获分组
    combined = "|".join(path_patterns + name_patterns)
    return rf"(?:{combined})"


def check_file_operations(logical_lines, all_found_scripts, custom_sensitive_list=None):
    """
    支持：
    1. 自定义敏感文件/目录/路径
    2. 项目内已搜寻到的脚本文件
    3. 通用脚本后缀
    4. 动态变量路径操作
    """
    findings = []
    if not custom_sensitive_list:
        custom_sensitive_list = []

    # --- 1. 数据分流预处理 ---
    dir_self_list = []  # 存储目录本身 (形如 /etc/)
    target_file_list = []  # 存储文件或通配符 (形如 /etc/passwd 或 /tmp/*)

    for path in custom_sensitive_list:
        if path.endswith('/'):
            # 目录本身逻辑：去掉末尾斜杠以便统一处理边界
            dir_self_list.append(path.rstrip('/'))
        else:
            # 文件或通配符逻辑
            target_file_list.append(path)

    # --- 2. 构建正则提取器 ---

    # A. 目录本身正则：匹配目录名后紧跟 (空格、引号、分号、行尾)
    # 使用 (?=\s|['\"|&;]|$) 确保不匹配子目录
    if dir_self_list:
        dir_patterns = [re.escape(d) for d in dir_self_list]
        sensitive_dir_self_regex = rf"(?:{'|'.join(dir_patterns)})/?(?=\s|['\"|&;]|$)"
    else:
        sensitive_dir_self_regex = r"(?!x)x"  # 不匹配任何内容的占位符

    # B. 文件及通配符正则：将 /tmp/* 转换为 /tmp/.*
    if target_file_list:
        file_patterns = []
        for f in target_file_list:
            escaped = re.escape(f).replace(r'\*', '.*')
            file_patterns.append(escaped)
        sensitive_target_pattern = rf"(?:{'|'.join(file_patterns)})"
    else:
        sensitive_target_pattern = r"(?!x)x"

    # --- 2. 处理已知脚本的匹配 ---
    # 我们不仅关注文件名，也关注这些脚本的相对/绝对路径
    known_script_patterns = []
    for s in all_found_scripts:
        known_script_patterns.append(re.escape(s))  # 完整路径
        known_script_patterns.append(rf"\b{re.escape(os.path.basename(s))}\b")  # 纯文件名

    known_scripts_regex = rf"(?:{'|'.join(known_script_patterns)})" if known_script_patterns else r"(?!x)x"

    # --- 3. 定义扫描规则矩阵 ---
    # 定义“修改”动作：覆盖、追加、sed原地修改、移动、删除、权限变更等
    MODIFY_OPS = r"(?:>|>>|tee|sed\s+-i|cp|mv|rm|chmod|chown|ln|tar|rsync)"
    # 定义“读取”动作：查看内容
    READ_OPS = r"(?:cat|grep|head|tail|more|less|vi|vim)"

    BASE_MODIFY_CMD = r"(?:tee|sed\s+-i|cp|mv|rm|chmod|chown|ln|tar|rsync)"

    file_rules = [
        {
            "id": "SENSITIVE_TARGET_MODIFY",
            "level": "High",
            "pattern": rf"{MODIFY_OPS}.*?{sensitive_target_pattern}",
            "desc": "对自定义敏感文件或目录执行了修改/删除操作"
        },
        {
            "id": "SENSITIVE_DIR_SELF_MODIFY",
            "level": "Critical",
            # 逻辑：指令或重定向 + [空格] + 敏感目录路径 + [边界断言]
            "pattern": rf"(?:(?:\b{BASE_MODIFY_CMD}\b\s+)|[>]{{1,2}}\s*){sensitive_dir_self_regex}",
            "desc": "对敏感目录本身执行了修改/删除操作（非目录下文件）"
        },
        {
            "id": "SENSITIVE_TARGET_READ",
            "level": "Medium",
            "pattern": rf"{READ_OPS}.*?{sensitive_target_pattern}",
            "desc": "对自定义敏感文件或目录执行了读取操作"
        },
        {
            "id": "KNOWN_SCRIPT_OVERWRITE",
            "level": "Critical",
            "pattern": rf"(?:(?:\b{MODIFY_OPS}\b\s+)|(?:>\s*|>>\s*))[^;&|]*?{known_scripts_regex}",
            "desc": "尝试修改或覆盖本项目目录中已存在的 Shell 脚本"
        },
        {
            "id": "EXT_SCRIPT_MODIFY",
            "level": "Medium",
            "pattern": rf"(?:^|[;&|])\s*\b{MODIFY_OPS}\b\s+[^;&|]*?\.(sh|py|php|js|html|cgi|pl)\b",
            "desc": "对脚本或网页类后缀文件执行了修改操作"
        },
        {
            "id": "DYNAMIC_PATH_OP",
            "level": "Medium",
            "pattern": rf"(?:^|[;&|])\s*(?:[\w./]*/)?\b{MODIFY_OPS}\b\s+[^;&|]*?\$",
            "desc": "对动态变量路径执行了高危操作"
        }
    ]

    # --- 4. 执行扫描 ---
    for item in logical_lines:
        content = item['content']
        for rule in file_rules:
            m = re.search(rule['pattern'], content, re.IGNORECASE)
            if m:
                findings.append({
                    "line": item['line_no'],
                    "code": content,
                    "matched": m.group(0).strip(),  # 新增
                    "rule_id": rule['id'],
                    "level": rule['level'],
                    "description": rule['desc']
                })
    return findings




def check_secrets(logical_lines, custom_keywords=None):
    """
    敏感信息提取模块：整合通用、云端、IoT及网络请求规则。
    """
    findings = []

    keywords_pattern = "|".join(custom_keywords)

    # 2. 规则库定义
    secret_rules = [
        # === A. 基础凭據赋值 (排除变量引用 $VAR) ===
        {
            "id": "HARDCODED_SECRET",
            "level": "High",
            # 匹配: key = "value" 但排除 key = $VAR
            "pattern": rf"\b({keywords_pattern})\b\s*=\s*['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "发现硬编码的敏感变量赋值"
        },
        {
            "id": "SECRET_COMPARISON",
            "level": "Medium",
            "pattern": rf"==\s*['\"]?(?!\$)[^#\s\n]+['\"]?.*?({keywords_pattern})",
            "desc": "在条件判断中硬编码了敏感比对值"
        },

        # === B. 经典数据库与协议凭据 ===
        {
            "id": "SSHPASS_USAGE",
            "level": "High",
            "pattern": r"sshpass\s+-p\s+['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "明文使用 sshpass 传递密码"
        },
        {
            "id": "DB_AUTH_PARAM",
            "level": "High",
            "pattern": r"\b(mysql|mariadb|redis-cli|psql)\b.*?-(a|p|password)['\"]?(?!\$)[^#\s\n]*",
            "desc": "数据库/缓存工具命令行包含明文凭据"
        },
        {
            "id": "SNMP_COMMUNITY",
            "level": "Medium",
            "pattern": r"snmp\w+\s+.*-c\s+['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "SNMP 使用硬编码的 Community String"
        },

        # === C. IoT 嵌入式场景专用 ===
        {
            "id": "MQTT_CREDENTIALS",
            "level": "High",
            "pattern": r"mosquitto_(sub|pub)\s+.*-(u|P)\s+['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "MQTT(Mosquitto) 命令行包含明文账户或密码"
        },
        {
            "id": "NVRAM_SENSITIVE_SET",
            "level": "Medium",
            "pattern": r"(nvram|fw_setenv)\s+set\s+.*(pass|psk|key|secret).*?=(?!\$)[^#\s\n]+",
            "desc": "在 IoT 非易失存储中硬编码敏感配置"
        },
        {
            "id": "WPA_PASSPHRASE_EXTRACT",
            "level": "High",
            "pattern": r"wpa_passphrase\s+.*?['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "WiFi(WPA) 配置工具直接使用明文 PSK"
        },
        {
            "id": "TELNET_EXPECT_LOGIN",
            "level": "High",
            "pattern": r"(telnet|expect).*?(user|pass|login).*?['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "IoT 调试脚本中包含 Telnet/Expect 自动登录凭据"
        },

        # === D. 云服务与内网穿透 (Cloud/Tunnel) ===
        {
            "id": "CLOUD_AK_SK",
            "level": "Critical",
            # 匹配典型的 AK/SK 格式，如 AWS, Alibaba, Azure
            "pattern": r"\b(AKIA[0-9A-Z]{16}|LTAI[0-9a-zA-Z]{10,24})\b",
            "desc": "发现疑似云服务商 AccessKey ID (AWS/Alibaba)"
        },
        {
            "id": "TUNNEL_AUTH_TOKEN",
            "level": "High",
            "pattern": r"(frpc|frps|ngrok|tinc)\b.*?(token|auth|key)\s*[:=]\s*['\"]?(?!\$)[^#\s\n]+['\"]?",
            "desc": "内网穿透或代理工具的认证 Token 泄露"
        },

        # === E. 网络请求参数 (Curl/Wget) ===
        {
            "id": "CURL_USER_PASS",
            "level": "High",
            "pattern": r"curl\s+.*-u\s+['\"]?(?!\$)[^#\s\n]+:[^#\s\n]+['\"]?",
            "desc": "curl 使用 -u 传递明文账户密码"
        },
        {
            "id": "HTTP_HEADER_TOKEN",
            "level": "Medium",
            "pattern": r"curl\s+.*-H\s+['\"]?Authorization:.*?(Bearer|Basic).*?['\"]?",
            "desc": "HTTP Header 中包含硬编码的认证令牌"
        },
        {
            "id": "URL_EMBEDDED_AUTH",
            "level": "High",
            "pattern": r"(http|https|ftp)://[^:\s]+:[^@\s]+@[\w\.-]+",
            "desc": "URL 字符串中直接嵌入了明文账户密码"
        }
    ]

    # --- 过滤场景：防止误报 ---
    # 排除 echo 打印提示信息，如 echo "Please input password:"
    EXCLUDE_PROMPT = r"echo\s+['\"].*?({})\b.*?['\"]".format(keywords_pattern)

    for item in logical_lines:
        content = item['content']

        # 预检查：如果这一行纯粹是打印提示语，直接跳过
        if re.search(EXCLUDE_PROMPT, content, re.IGNORECASE):
            continue

        for rule in secret_rules:
            m = re.search(rule['pattern'], content, re.IGNORECASE)
            if m:
                findings.append({
                    "line": item['line_no'],
                    "code": content,
                    "matched": m.group(0).strip(),  # 新增
                    "rule_id": rule['id'],
                    "level": rule['level'],
                    "description": rule['desc']
                })

    return findings


def check_sensitive_operations(file_full_text, logical_lines, custom_cmds=None):
    findings = []


    custom_cmds_regex = "|".join([re.escape(c) for c in custom_cmds])

    # --- 策略 A: 改进后的长链路扫描 (解决 Python 正则报错问题) ---
    dl_commands = r"(?:curl|wget|ftp|sftp|rsync|scp)"
    dl_pattern = rf"\b{dl_commands}\b"

    # 优化后的执行特征 (移除了变长后瞻断言，改为使用捕获组包含前缀)
    # 模式说明：
    # 1. chmod 授权
    # 2. 解释器执行
    # 3. 只有在行首或分号/管道等分隔符后出现的路径才视为执行
    exec_pattern = r"(\bchmod\s+(?:\+x|[0-7]{3,4})|\b(?:sh|bash|eval|source)\s+|(?:^|[;&|\n])\s*(?:\./|/(?:data|tmp|var|dev/shm)/)[\w\.\-/]+)"

    downloads = list(re.finditer(dl_pattern, file_full_text, re.IGNORECASE))
    # 注意：这里使用 re.MULTILINE 配合 ^ 符号
    executions = list(re.finditer(exec_pattern, file_full_text, re.MULTILINE))

    for dl in downloads:
        for ex in executions:
            dist = ex.start() - dl.end()
            # 确保执行在下载后，且距离在 1000 字符内
            if 0 < dist < 1000:
                # 获取下载点所在的行结束位置，用于判断 ex 是否在同一行
                dl_line_end = file_full_text.find('\n', dl.start())
                if dl_line_end == -1: dl_line_end = len(file_full_text)

                # 逻辑过滤：如果执行点在下载点同一行，且不是明确的 chmod/sh/bash 等命令
                # 则判定该路径只是下载命令的参数（如 ftp -l /tmp/file），不构成执行链
                is_explicit_exec = any(keyword in ex.group(0) for keyword in ['chmod', 'sh', 'bash', 'eval', 'source'])
                if ex.start() < dl_line_end and not is_explicit_exec:
                    continue

                line_no = file_full_text.count('\n', 0, dl.start()) + 1
                findings.append({
                    "line": line_no,
                    "rule_id": "LONG_RCE_CHAIN",
                    "level": "Critical",
                    "description": "检测到跨行远程下载执行链：下载后紧跟授权或独立执行动作",
                    "code": file_full_text[dl.start():ex.end()].strip(),
                    "matched": f"{dl.group(0)}...{ex.group(0).strip()}"
                })
                break

    # --- 策略 B: 逻辑行精确匹配 ---
    ops_rules = [
        # 需求 2: 单独添加下载操作匹配规则
        {
            "id": "REMOTE_DL_OP",
            "level": "Low",
            "pattern": rf"\b{dl_commands}\b",
            "desc": "检测到远程下载或文件传输相关命令"
        },
        {
            "id": "CUSTOM_CMD_WATCH",
            "level": "Low",
            "pattern": rf"\b({custom_cmds_regex})\b",
            "desc": "命中用户定义的敏感监控命令"
        },
        {
            "id": "ENV_HIJACK",
            "level": "High",
            "pattern": r"(?:^|[;&|])\s*(?<!local\s)(?<!typeset\s)(?:export\s+)?\b(PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)\b\s*=\s*['\"]?[^;|\s\n]*?\$(?!(?:{)?\1\b)[\w{}]+",
            "desc": "环境变量被设置为含变量的动态路径，存在劫持风险"
        },
        {
            "id": "DYNAMIC_EXPORT",
            "level": "Medium",
            "pattern": r"export\s+\$\w+",
            "desc": "通过变量名动态导出环境变量，可能导致环境污染"
        }
    ]

    for item in logical_lines:
        content = item['content']
        for rule in ops_rules:
            m = re.search(rule['pattern'], content, re.IGNORECASE)
            if m:
                findings.append({
                    "line": item['line_no'],
                    "rule_id": rule['id'],
                    "level": rule['level'],
                    "description": rule['desc'],
                    "code": content,
                    "matched": m.group(0).strip()
                })

    return findings


# --- [此处省略你提供的基础函数: is_shell_script, get_logical_lines, build_sensitive_regex 等] ---
# 注意：为了让多进程池工作，建议将被调用的检测函数放在同一个类中或作为全局函数

class ShellSecurityScanner:
    def __init__(self, custom_sensitive_list=None, custom_keywords=None, custom_cmds=None):
        # 统一设为拓展模式

        self.custom_sensitive_list = list(set((custom_sensitive_list or [])))
        self.custom_keywords = list(set((custom_keywords or [])))

        self.custom_cmds = custom_cmds
        self.all_found_scripts = []

    def _get_full_text_clean(self, file_path):
        """获取去注释的全文本，用于长链路分析"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return re.sub(r'#.*', '', content)
        except:
            return ""

    def scan_single_file(self, file_path):
        """对单个文件运行所有检测模块"""
        findings = []
        try:
            # 1. 基础数据准备
            clean_full_text = self._get_full_text_clean(file_path)
            logical_lines = get_logical_lines(file_path)

            # 2. 调用各个检测模块 (这些函数需在全局作用域定义)
            findings.extend(check_command_injection(logical_lines))
            findings.extend(check_argument_injection(logical_lines))
            findings.extend(check_file_operations(logical_lines, self.all_found_scripts, self.custom_sensitive_list))
            findings.extend(check_secrets(logical_lines, self.custom_keywords))
            findings.extend(check_sensitive_operations(clean_full_text, logical_lines, self.custom_cmds))

            # 3. 填充路径信息
            for f in findings:
                f['file_path'] = str(file_path)
            return findings
        except Exception as e:
            return [{"file_path": str(file_path), "level": "Error", "description": f"Scan failed: {str(e)}"}]

    def run_scan(self, target_path, output_file=None):
        target = pathlib.Path(target_path).absolute()

        if not target.exists():
            print(f"[-] Error: Target path {target} does not exist.")
            return

        # 如果是目录，先收集全项目脚本用于上下文关联
        if target.is_dir():
            print(f"[*] Searching for scripts in {target}...")
            self.all_found_scripts = get_all_shell_files(target)
            print(f"[*] Found {len(self.all_found_scripts)} scripts. Scanning...")

            all_results = []
            # 多进程并行处理
            with concurrent.futures.ProcessPoolExecutor() as executor:
                future_to_file = {executor.submit(self.scan_single_file, f): f for f in self.all_found_scripts}
                for future in concurrent.futures.as_completed(future_to_file):
                    all_results.extend(future.result())
        else:
            # 单文件模式
            print(f"[*] Scanning single file: {target}")
            all_results = self.scan_single_file(target)

        # 结果输出逻辑
        if output_file:
            self._save_to_file(all_results, output_file)
        else:
            self._print_results(all_results)

        return all_results

    def _print_results(self, results):
        if not results:
            print("[+] No security issues found.")
            return

        # 增加 MATCHED 列名，并调整宽度
        print(f"\n{'LEVEL':<10} {'LINE':<6} {'RULE_ID':<22} {'MATCHED':<20} {'DESCRIPTION'}")
        print("-" * 120)

        for r in sorted(results, key=lambda x: (x.get('file_path', ''), x.get('line', 0))):
            level = r.get('level', 'N/A')
            line = r.get('line', 'N/A')
            rule_id = r.get('rule_id', 'N/A')
            desc = r.get('description') or r.get('desc', 'N/A')
            f_path = r.get('file_path', '')

            # 提取匹配内容并做截断处理
            matched = str(r.get('matched', 'N/A'))
            if len(matched) > 17:
                matched = matched[:14] + "..."

            print(f"{level:<10} {line:<6} {rule_id:<22} {matched:<20} [{f_path}] {desc}")

    def _save_to_file(self, results, output_file):
        # 统计逻辑增强：确保即便某个等级数量为 0 也能在报告中体现
        severity_map = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Error": 0}
        for r in results:
            lv = r.get('level', 'Low')
            severity_map[lv] = severity_map.get(lv, 0) + 1

        output_data = {
            "scan_info": {
                "target_path": str(
                    pathlib.Path(self.all_found_scripts[0]).parent if self.all_found_scripts else "Single File"),
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_issues": len(results),
                "severity_distribution": severity_map  # 使用预定义的字典，输出更整齐
            },
            # 此时 results 里的每个字典已经包含了 'matched' 键值对
            "results": results
        }

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # ensure_ascii=False 保证 matched 里的中文或特殊字符不被转码
                json.dump(output_data, f, indent=4, ensure_ascii=False)
            print(f"\n[+] Scan complete. {len(results)} issues saved to: {output_file}")
        except Exception as e:
            print(f"[-] Failed to save report: {e}")


def sort_json_report(input_path, output_path):
    """
    读取结果文件，按风险等级(Level)从高到低排序后写入新文件。
    优先级: Critical > Error > High > Medium > Low
    """
    # 1. 定义风险等级权重
    level_weights = {
        "Critical": 5,
        "Error": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    try:
        # 2. 读取原始文件
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if "results" in data and isinstance(data["results"], list):
            # 3. 执行排序
            # 排序逻辑：主关键字是风险权重(降序)，次关键字是文件路径(升序)，再次是行号(升序)
            data["results"].sort(
                key=lambda x: (
                    -level_weights.get(x.get("level", "Low"), 0),  # 负号实现降序
                    x.get("file_path", ""),
                    x.get("line", 0)
                )
            )
            print(f"成功对 {len(data['results'])} 条结果进行排序。")
        else:
            print("警告：未在 JSON 中找到 'results' 列表。")

        # 4. 写入新文件
        with open(output_path, 'w', encoding='utf-8') as f:
            # ensure_ascii=False 保证中文正常显示，indent=4 保证格式美观
            json.dump(data, f, ensure_ascii=False, indent=4)

        print(f"排序后的结果已保存至: {output_path}")

    except FileNotFoundError:
        print(f"错误：找不到文件 {input_path}")
    except json.JSONDecodeError:
        print(f"错误：{input_path} 不是有效的 JSON 文件")
    except Exception as e:
        print(f"发生未知错误: {e}")


def sort_json_report(input_path, output_path):
    """
    读取结果文件，按风险等级(Level)从高到低排序后写入新文件。
    优先级: Critical > Error > High > Medium > Low
    """
    # 1. 定义风险等级权重
    level_weights = {
        "Critical": 5,
        "Error": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    try:
        # 2. 读取原始文件
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if "results" in data and isinstance(data["results"], list):
            # 3. 执行排序
            # 排序逻辑：主关键字是风险权重(降序)，次关键字是文件路径(升序)，再次是行号(升序)
            data["results"].sort(
                key=lambda x: (
                    -level_weights.get(x.get("level", "Low"), 0),  # 负号实现降序
                    x.get("file_path", ""),
                    x.get("line", 0)
                )
            )
            print(f"成功对 {len(data['results'])} 条结果进行排序。")
        else:
            print("警告：未在 JSON 中找到 'results' 列表。")

        # 4. 写入新文件
        with open(output_path, 'w', encoding='utf-8') as f:
            # ensure_ascii=False 保证中文正常显示，indent=4 保证格式美观
            json.dump(data, f, ensure_ascii=False, indent=4)

        print(f"排序后的结果已保存至: {output_path}")

    except FileNotFoundError:
        print(f"错误：找不到文件 {input_path}")
    except json.JSONDecodeError:
        print(f"错误：{input_path} 不是有效的 JSON 文件")
    except Exception as e:
        print(f"发生未知错误: {e}")


# --- 启动逻辑 ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gemini Shell Security Scanner - IoT Edition")

    # 核心参数
    parser.add_argument("target", help="目标文件或目录路径")
    parser.add_argument("-o", "--output", help="输出文件名 (例如 report.json)，不指定则打印到屏幕")

    # 拓展参数
    parser.add_argument("--keys", nargs='+', help="拓展敏感关键字，例如 --keys token secret_v2")
    parser.add_argument("--files", nargs='+', help="拓展敏感文件路径，例如 --files /etc/shadow /tmp/bak")

    args = parser.parse_args()

    # 敏感文件 目录
    # 目录分两种：1./tmp/ 以/结尾的目录，进匹配对该目录的操作；2./tmp/*以*结尾的目录，匹配该目录下的任意文件的操作
    custom_sensitive_list = ['/etc/passwd','/etc/shadow', '/etc/cron.d/*', 'openvpn.conf', 'snmpd.conf', '/var/spool/cron/*', '/tmp/*','lighttpd.conf','nginx.conf','rsyncd.conf','sshd_config','.ssh/*',
                             'vsftpd.conf','proftpd.conf','pure-ftpd.conf','/pure-ftpd/*','inetd.conf','xinetd.conf','xinetd.d/*','/etc/rc.local/*','/etc/systemd/system/*','/etc/profile','/etc/bash.bashrc',
                             '.bashrc','.profile','redis.conf','.htaccess','/etc/ld.so.preload','/etc/exports']
    custom_sensitive_list.extend(args.files or [])
    # 敏感关键字提取敏感信息
    default_keywords = ['password', 'passwd', 'secret', 'token', 'credential', 'auth_key', 'passphrase']
    default_keywords.extend(args.keys or [])
    # 敏感操作列表
    # custom_cmds = ['nvram get', 'fw_printenv', 'get_config', 'nvram set']
    # 添加命令时考虑误报，例如'rm -rf /'会匹配到'rm -rf /aaa'
    custom_cmds = ['rm -rf / ','rm -rf /;','reboot']
    # 初始化引擎
    scanner = ShellSecurityScanner(
        custom_sensitive_list=custom_sensitive_list,
        custom_keywords=default_keywords,
        custom_cmds=custom_cmds
    )

    # 运行扫描
    scanner.run_scan(args.target, output_file=args.output)

    sort_json_report(args.output, args.output)

