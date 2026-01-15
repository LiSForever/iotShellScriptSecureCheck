# iotShellScriptCheck

扫描iot设备的后台，搜索所有shell脚本，并发现其中的值得关注地方

# 待完成

* python开发
* 功能
  * 扫描后台，找到所有shell脚本
  * 匹配值得关注的内容（不进行数据流追踪）
    * 命令注入
    * 危险命令参数注入
    * 敏感文件操作
      * /etc/passwd 计划任务等系统文件；服务的配置文件（可自定义）
      * 可执行脚本
      * 任意文件/目录的写/读取/删除
    * 敏感操作
      * nvram get xxx（自定义命令）
      * curl http://xxx | bash -c（等高危操作）
      * 环境变量劫持
    * 敏感信息
      * password 等关键字匹配（自定义关键字）
      * ssh、ftp等命令提取（敏感命令提取）
* 优化
  * 对结果按照危险程度进行排序（DONE）
  * 二次过滤，处理第一次匹配的结果（DONE）
    * AI也会存在幻觉
  * 优化正则
    * 优化WRAPPER_EXEC \b(eval|exec|source|sh|bash|zsh)\b\s+.*\$ 匹配到了/usr/bin/check-dbus.sh "$1"（DONE）
    * 同上优化PIPE_TO_SHELL（DONE）
    * 环境变量被设置为含变量的动态路径，存在劫持风险 匹配 local path=$1（DONE）
    * 对脚本或网页类后缀文件执行了修改操作 匹配 . /app/bin/startGatt.sh（DONE）
    * 对动态变量路径执行了高危操作 sed -i s/\>80\</\>$HTTP\</g /tmp/config/services/http.service 考虑完善对引号的识别 （DONE，规则匹配放弃引号识别）
    * 检测到跨行远程执行链：从远程下载到授权或直接执行(路径/chmod) （TODO） ftp -p -l "/tmp/meminfo/stats- 只有下载动作也被识别，将只有下载和完整执行链分开（DONE）
    * 尝试修改或覆盖本项目目录中已存在的 Shell 脚本 RMAN_CMD='/app/bin/doorman.sh （DONE）
    * 对动态变量路径执行了高危操作 if isIPv4DHCP $1; then （DONE）
    * 尝试修改或覆盖本项目目录中已存在的 Shell 脚本 "matched": "tarting atd" "code": "syslog \"Starting atd\""（DONE）
  * 某一个规则的命令太泛了，规则需要迁移和细化(TODO)
    * /tmp/目录操作和目录下的文件操作分开（TODO）
    * 文件操作区分最后的文件是动态的，还是路径是动态的（TODO）
  * 补充规则
    * 敏感操作：参数展开，没有使用引号括起（DONE，暂不实现）
      * 1.容易产生大量误报
      * 2.针对特定命令的检测，已经被其他规则所覆盖
    * 敏感操作：insmod加载模块（DONE）
    * 动态nvram get和动态nvram set，由此扩展一下自定义动态命令（DONE，不好实现，暂不添加）
    * 增加配置文件
      * AMI
      * rsync
      * ftp
      * sftp
      * ssh等
    * 敏感操作增加命令gzip（DONE）
    * 增加了一些敏感目录和敏感配置文件（DONE）