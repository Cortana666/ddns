# ddns
更改域名解析IP地址，主要用于公网IP不定时变化的家庭宽带
---  
使用定时任务执行脚本，实现定时检测IP变化并修改DNS解析记录中的IP地址
---
特性：
- IP无变化不执行解析变更
- 支持CloudFlare、阿里云、腾讯云、NameSilo(需优化，NameSilo解析记录修改后记录ID会变更)、域名解析修改
- 支持A、AAAA记录解析修改，默认为A记录
- ~~支持不必使用解析记录ID，仅使用域名修改解析记录IP~~
---
命令参数：
```
--ip_server             默认为https://api.ipify.org/，要获取IPv6地址使用https://api6.ipify.org/，也可使用其它获取客户端IP的网络服务地址
--ip_server_key         默认为root，获取IP服务的响应结构，响应为x.x.x.x字符串即ip地址时传入root，响应为JSON时传入ip地址对应的key（只支持一维JSON）
--dns_server            DNS解析服务商，CloudFlare传入cf，阿里传入al，腾讯传入tc，NameSilo传入ns， 暂不支持其它
--dns_id                DNS解析记录ID
--record_type           默认为A，记录类型，仅支持A、AAAA
--host_record           主机记录
--api_key               API令牌
--zone_id               CloudFlare区域ID
--api_secret            API密钥
--domain                腾讯云DNS解析二级域名
```
---
示例：  
CloudFLare:
```shell
ddns --dns_server cf --host_record www --dns_id "123456" --api_key "123456" --zone_id "123456"
```
阿里云：
```shell
ddns --dns_server al --host_record www --dns_id "123456" --api_key "123456" --api_secret "123456"
```
腾讯云：
```shell
ddns --dns_server tc --host_record www --dns_id "123456" --api_key "123456" --api_secret "123456" --domain abc.com
```
NameSilo：
```shell
ddns --dns_server ns --host_record www --dns_id "123456" --api_key "123456" --domain abc.com
```