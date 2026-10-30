# SiteLens 自研协议模板（curated-proto）

3.0 协议模板的自研精选集：全部为 banner 级只读探测（连接即回显 / 无副
作用命令），与官方 network 模板零重复（官方未覆盖的服务或更早的版本
信号）。经漏斗准入后随模板池调度，源码在本目录入库。

| 模板 | 服务 | 探测 | 判定 |
|---|---|---|---|
| memcached-banner | memcached 11211 | `version\r\n` | `VERSION ` 前缀 |
| ftp-banner | FTP 21 | 连接读 banner | `220 ` |
| ssh-banner | SSH 22 | 连接读 banner | `SSH-` |
| mysql-greeting | MySQL 3306 | 连接读握手包 | 握手包长度字节 + `mysql_native_password`/版本段 |
| vnc-banner | VNC 5900 | 连接读 banner | `RFB ` |
| redis-sliv | Redis 6379 | 复官方（对齐官方 redis-detect 以内网判别为准） | 官方覆盖，不重复收录 |

> 收录原则：只加官方 network 没有的服务/信号；判定串取服务协议固有
> 回显，避免弱特征误报；不做任何写命令（禁 SET/FLUSH/eval 等）。
