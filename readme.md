# CThun
CThun是集成快速端口扫描,服务识别,netbios扫描,网站识别和暴力破解的工具.

# 优点
* 端口扫描扫描速度快(255个IP,TOP100端口,15秒)
* 服务识别准确(集成NMAP指纹数据库)
* 单文件无依赖(方便内网扫描)
* 适应性强(Windows Server 2012,CentOS6,Debain9,ubuntu16)
* 支持多种协议暴力破解
* 支持netbios扫描(获取多网卡ip)
* 支持vul扫描(ms17-010)

# 缺点
* 可执行文件大(20M)
* 不支持Windows Server 2003/Windows XP

# 依赖
* RDP的暴力破解依赖OpenSSL(Windows Server 2003/Windows XP不能使用rdp暴力破解,其他功能无影响)
* Linux服务器需要glibc版本大于2.5(高于centos5,ldd --version查看)

# 漏洞列表
* ms17-010
* CVE_2019_3396
* CVE_2017_12149
* S2_015
* S2_016
* S2_045
* CVE_2017_12615
* CVE_2017_10271
* CVE_2018_2894
* CVE_2019_2729

# 使用方法
* 修改param.json中参数
* 将可执行文件cthun.exe及param.json上传到已控制主机
* 直接运行cthun.exe

# 已测试
* Windows server 2003
* Windows7
* Windows Server 2012
* CentOS5
* Kali

# 工具截图


# 更新日志
**1.0 beta**
更新时间: 2021-07-12
- 发布第一个版本

cthun(克苏恩)是魔兽世界电子游戏中一位上古之神

