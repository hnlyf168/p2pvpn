# 访问与下载统计

管理员登录后打开 `/ops#traffic`，可查看今日访问与安装包下载、近 7/30/90 天趋势、逐日明细和安装包排行。仅管理员可以读取 `/admin/traffic?days=30`，普通用户和未登录请求均被拒绝。

- 日期按北京时间（Asia/Shanghai，UTC+8）切分，范围包含今天，没有记录的日期补零。
- 访问次数是官网 HTML 页面成功返回的 GET 请求次数（PV），不是独立访客人数；不计用户控制台、运营后台、API、静态资源和健康检查。爬虫请求也可能计入。
- 下载次数是官网安装包成功响应的请求次数；在线安装器获取安装包也计入。完整 200 响应、从第 0 字节开始的单段 206 响应计一次；HEAD、304、失败和后续续传分片不计入。不能据此判断用户是否完成安装，重复从头下载仍会再次计数。GitHub 直接下载不经过官网，不计入这里。
- `/install.sh`、`/install.ps1`、`/install.cmd` 获取次数单独列出，不与安装包混算。
- 仅保存每日汇总与公开安装包文件名，不保存 IP、邮箱、查询字符串、Cookie 或安装票据。

统计文件是 `DataDirectory/traffic-statistics.json`，与账号数据库分开。每 10 秒原子保存一次，正常停止时立即保存；异常断电可能丢失最后一个周期。保留 400 天，后台可查询最近 90 天。请把该文件纳入私有备份，不要放进源码或发布包。如果文件损坏或磁盘不可写，后台显示异常提示，原文件保持不变，账号与组网服务继续运行。

## 迁移已有日志

仅用于第一次启用统计，先停止控制服务，再运行：

```sh
python3 tools/import-traffic-history.py --log-directory /var/log/nginx --output /var/lib/edge-vpn-control/traffic-statistics.json
chown edgevpn:edgevpn /var/lib/edge-vpn-control/traffic-statistics.json
```

脚本读取 `vpn-site-access.log*`（支持 `.gz`）中的 JSON 行，字段为 `time`、`method`、`uri`、`status`。仅输出聚合数据，拒绝覆盖现有统计文件，重复输入同一个日志文件不会重复计算。旧日志没有 Range 信息，所以只导入完整 200 响应，不回填 206。恢复的日期范围受日志保留时间限制，早于日志的数据无法推算。完成后启动控制服务，后续统计直接由应用记录，不依赖 Python 或读取 Nginx 日志权限。

## 验证

```sh
dotnet run --project tests/Traffic -c Release
dotnet run --project tests/Integration -c Release
python -m unittest discover -s tests/Release -v
```

界面检查：设置 `PLAYWRIGHT_MODULE` 指向 Playwright 模块后执行 `node tools/traffic-browser-check.cjs`，可用 `BROWSER_PATH` 指定浏览器。该脚本使用隔离的临时管理员、合成统计数据与独立端口，截图写入 `artifacts/traffic-browser/`。
