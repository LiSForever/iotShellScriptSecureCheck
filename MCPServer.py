# audit_server.py
from mcp.server.fastmcp import FastMCP
import os

# 创建一个名为 "AuditHelper" 的 MCP 服务
mcp = FastMCP("AuditHelper")


@mcp.tool()
def get_code_context(file_path: str, line: int, window: int = 10) -> str:
    """
    根据文件路径和行号，读取代码上下文。
    :param file_path: 脚本文件的绝对路径
    :param line: 命中规则的行号
    :param window: 向上和向下获取的行数偏移量
    """
    if not os.path.exists(file_path):
        return f"错误：找不到文件 {file_path}"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        start = max(0, line - window - 1)
        end = min(len(lines), line + window)

        # 格式化输出代码块，带上行号
        context = []
        for i in range(start, end):
            prefix = ">> " if i + 1 == line else "   "
            context.append(f"{prefix}{i + 1}: {lines[i].strip()}")

        return "\n".join(context)
    except Exception as e:
        return f"读取文件失败: {str(e)}"


if __name__ == "__main__":
    mcp.run()