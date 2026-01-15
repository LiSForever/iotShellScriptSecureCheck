### iotShellScriptCheck
* 用于扫描iot设备的所有shell脚本，基于正则规则匹配其中的值得关注地方
* 目前误报还是较多，但是相比于逐个脚本人工审计，还是轻松不少

### 用法
* iotShellScriptCheck.py 会对指定目录进行静态扫描，并输出结果
```shell
 python iotShellScriptCheck.py /any/path/you/want/to/scan -o output.json
```
* audit_agent.py 可以对静态输出结果进行AI审计，筛选误报和真实的漏洞
  * 使用时，需要在脚本中配置输入输出文件，在.env中配置deepseek的key

### 规则
静态扫描规则会匹配如下内容：
* 命令注入
  * 变量直接作为命令执行
  * 使用包装器执行动态内容 (eval/exec/bash -c)
  * 在反引号或子shell中执行变量
  * 使用 '.' 缩写执行动态脚本
  * 通过管道将变量内容传递给Shell执行
* 危险命令参数注入
  * find 关键参数(-exec等)包含动态变量，极高注入风险
  * find 包含动态参数，需人工确认变量来源是否可信
  * xargs 将内容传递给解释器处理且包含变量
  * xargs 涉及动态变量，可能存在参数注入
  * tcpdump 使用 -z 执行动态脚本，极高风险
  * tcpdump 命令包含动态变量
  * ssh ProxyCommand 包含动态变量，可导致命令执行
  * ssh 目标或命令包含动态变量
  * tar 通过 checkpoint 机制执行动态命令
  * tar 备份路径或参数包含动态变量
  * curl 从变量指定的文件读取配置，可能导致敏感信息泄露
  * 网络请求工具包含动态参数
* 文件操作
  * 对自定义敏感文件或目录执行了修改/删除操作
  * 对敏感目录本身执行了修改/删除操作（非目录下文件）
  * 对自定义敏感文件或目录执行了读取操作
  * 尝试修改或覆盖本项目目录中已存在的 Shell 脚本
  * 对脚本或网页类后缀文件执行了修改操作
  * 对动态变量路径执行了高危操作
* 敏感信息匹配
  * 发现硬编码的敏感变量赋值（自定义关键字）
  * 在条件判断中硬编码了敏感比对值
  * 明文使用 sshpass 传递密码
  * 数据库/缓存工具命令行包含明文凭据
  * SNMP 使用硬编码的 Community String
  * MQTT(Mosquitto) 命令行包含明文账户或密码
  * 在 IoT 非易失存储中硬编码敏感配置
  * WiFi(WPA) 配置工具直接使用明文 PSK
  * IoT 调试脚本中包含 Telnet/Expect 自动登录凭据
  * 发现疑似云服务商 AccessKey ID (AWS/Alibaba)
  * 内网穿透或代理工具的认证 Token 泄露
  * curl 使用 -u 传递明文账户密码
  * HTTP Header 中包含硬编码的认证令牌
  * URL 字符串中直接嵌入了明文账户密码
* 其他敏感操作
  * 检测到跨行远程下载执行链：下载后紧跟授权或独立执行动作
  * 检测到远程下载或文件传输相关命令
  * 命中用户定义的敏感监控命令
  * 环境变量被设置为含变量的动态路径，存在劫持风险
  * 通过变量名动态导出环境变量，可能导致环境污染

### 自定义内容
```python
# 敏感文件 目录
# 目录分两种：1./tmp/ 以/结尾的目录，进匹配对该目录的操作；2./tmp/*以*结尾的目录，匹配该目录下的任意文件的操作
custom_sensitive_list = ['/etc/passwd','/etc/shadow', '/etc/cron.d/*', 'openvpn.conf', 'snmpd.conf', '/var/spool/cron/*', '/tmp/*','lighttpd.conf','nginx.conf','rsyncd.conf','sshd_config','.ssh/*',
                         'vsftpd.conf','proftpd.conf','pure-ftpd.conf','/pure-ftpd/*','inetd.conf','xinetd.conf','xinetd.d/*','/etc/rc.local/*','/etc/systemd/system/*','/etc/profile','/etc/bash.bashrc',
                         '.bashrc','.profile','redis.conf','.htaccess','/etc/ld.so.preload','/etc/exports']

# 敏感关键字提取敏感信息
default_keywords = ['password', 'passwd', 'secret', 'token', 'credential', 'auth_key', 'passphrase']

# 添加命令时考虑误报，例如'rm -rf /'会匹配到'rm -rf /aaa'
custom_cmds = ['rm -rf / ','rm -rf /;','reboot']
```

### 优化/规划 记录
* ...