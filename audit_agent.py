import json
import os
from openai import OpenAI
from MCPServer import get_code_context  # 确保 audit_server.py 在同级目录
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

load_dotenv()

WRITE_LOCK = Lock()  # 确保多个线程不会同时写入同一个文件导致损坏
MAX_THREADS = 20     # 并发数，根据你的 API 配额调整（建议 5-10

# --- 配置区 ---
DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY')
INPUT_FILE = "startWebNew.json"  # 你的原始扫描结果文件
FP_OUTPUT_FILE = "false_positives.json"  # 误报存储文件
REAL_OUTPUT_FILE = "real_issues.json"  # 真报存储文件
# --------------



def audit_single_result(result,client):
    """对单条扫描结果进行 AI 审计"""
    print(f"[*] 正在分析: {result.get('file_path')} | Line: {result.get('line')}")

    # 1. 获取上下文 (扩展到 50 行以获得更精准的判断)
    context_code = get_code_context(result['file_path'], result['line'], window=50)

    # 2. 构造 Prompt (沿用你的严格判断标准)
    messages = [
        {
            "role": "system",
            "content": "你是一个资深 Linux 安全审计专家。你的任务是分析静态扫描器输出的告警，判断其是否为误报(False Positive)。"
        },
        {
            "role": "user",
            "content": f"""
                    请核查以下代码是否存在安全风险：

                    【告警详情】
                    规则：{result['rule_id']} ({result['description']})
                    匹配：{result['matched']} ({result['code']}) 
                    文件：{result['file_path']}

                    【上下文代码】
                    {context_code}

                    【分析要求】
                    危险数据的来源有：
                    1.脚本参数
                    2.配置文件
                    3.包括nvram get在内的命令获取
                    4.任何其他不是硬编码的来源

                    对于误报的判断非常严格，有且仅有以下几种情况：
                    1. 命令注入：动态变量的来源是硬编码，没有注入风险
                    2. 命令注入：匹配的关键字，实际上是字符串，而非可执行的命令
                    3. 参数注入：动态变量的来源是硬编码，没有注入风险
                    4. 参数注入：匹配的关键字，实际上是字符串，而非可执行的命令
                    5. 文件操作：写入文件的内容没有动态变量
                    6. 文件操作：写入文件的内容有动态变量，但来源是硬编码
                    7. 文件操作：匹配的文件，实际上是字符串，而非可执行的命令
                    8. 敏感信息：请根据结果中的敏感信息自行分析是否是误报
                    9. 敏感操作：动态变量的来源是硬编码，没有注入风险
                    10. 敏感操作：匹配的操作，实际上是字符串，而非可执行的命令
                    请以 JSON 格式输出：
                    {{
                        "is_false_positive": bool,
                        "confidence": float (0-1),
                        "reason": "你的深度分析理由",
                        "suggestion": "修复或优化建议"
                    }}
                    """
        }
    ]

    try:
        # 使用 deepseek-reasoner (R1) 进行深度思考
        response = client.chat.completions.create(
            model="deepseek-reasoner",
            messages=messages,
            stream=False
        )

        # 解析 AI 返回内容
        content = response.choices[0].message.content
        # 针对有些模型可能返回 ```json ... ``` 的情况进行清洗
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()

        ai_analysis = json.loads(content)

        # 将 AI 的分析合并到原始结果中
        result.update({
            "ai_is_fp": ai_analysis.get("is_false_positive"),
            "ai_reason": ai_analysis.get("reason"),
            "ai_suggestion": ai_analysis.get("suggestion"),
        })

        return result

    except Exception as e:
        print(f"[!] 审计出错: {e}")
        return None


# --- [新增代码：线程安全的保存函数] ---
def save_entry(item, is_fp):
    """当一条结果处理完，立即加锁写入文件"""
    filename = "false_positives.json" if is_fp else "real_issues.json"

    with WRITE_LOCK:
        data = []
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except:
                    data = []

        data.append(item)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)


# ----------------------------------

# 修改后的执行入口
if __name__ == "__main__":
    # 初始化客户端
    client = OpenAI(
        api_key=DEEPSEEK_API_KEY,
        base_url="https://api.deepseek.com"
    )

    # 读取原始 540 条结果
    with open("startWebNew.json", 'r', encoding='utf-8') as f:
        all_data = json.load(f)
    issues_list = all_data['results']

    print(f"[*] 开始多线程审计，总计: {len(issues_list)} 条，并发线程: {MAX_THREADS}")

    # --- [核心变动：使用线程池替代普通 for 循环] ---
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # 提交所有任务
        future_to_item = {executor.submit(audit_single_result, item, client): item for item in issues_list}

        count = 0
        for future in as_completed(future_to_item):
            count += 1
            result_item = future.result()

            if result_item:
                # 根据 AI 的判断分流保存
                is_fp = result_item.get("ai_is_fp", False)
                save_entry(result_item, is_fp)

                label = "❌ 误报" if is_fp else "⚠️ 真报"
                print(f"[{count}/{len(issues_list)}] 已处理: {result_item['file_path']} -> {label}")
    # ----------------------------------------------

    print("\n[√] 批量审计任务全部完成。")