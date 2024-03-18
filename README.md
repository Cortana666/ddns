# ddns
更改域名解析IP地址（仅限A记录）
---  
使用定时任务执行脚本，实现定时检测IP变化并修改DNS解析记录中的IP地址
---
特性：
- IP不变化不执行解析变更
- 支持CloudFlare使用解析ID修改IP
---
将来要做的：
- ~~支持阿里云域名解析~~
- 支持腾讯云域名解析
- 支持NameSilo域名解析
- 支持AAAA记录IPV6地址解析修改
- 支持仅使用域名修改解析记录