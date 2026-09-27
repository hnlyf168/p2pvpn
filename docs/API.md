# API

浏览器登录/注册带 X-Session-Mode: cookie，返回 csrfToken 并设置 HttpOnly 会话 Cookie；后续写请求携带 X-CSRF-Token。非浏览器 API 仍兼容 Authorization: Bearer <登录令牌>，设备使用独立凭据。
设备 API 使用独立设备令牌。加入接口只使用限时限次加入密钥。
敏感响应设置 no-store；密钥不要放 URL 查询参数。

| 方法 | 路径 | 权限／内容 |
|---|---|---|
| POST | /api/register | {email,password}，密码 12–128 位，返回登录令牌 |
| POST | /api/login | {email,password} |
| POST | /api/logout | 吊销当前登录令牌 |
| GET | /api/me | 当前套餐与限额 |
| GET / POST | /api/networks | 查看本人网络／{name} 创建 |
| DELETE | /api/networks/{id} | 删除本人网络及密钥设备 |
| POST | /api/networks/{id}/groups | {name} 创建隔离分组 |
| DELETE | /api/networks/{id}/groups/{groupId} | 删除无有效设备的分组，至少保留一个 |
| POST | /api/networks/{id}/keys | {name,groupId,uses,validHours}；明文 key 仅返回一次 |
| DELETE | /api/networks/{id}/keys/{keyId} | 吊销加入密钥 |
| DELETE | /api/networks/{id}/devices/{deviceId} | 吊销设备 |
| POST | /api/networks/{id}/rotate | 轮换握手与组数据密钥 |
| POST | /api/enroll | {key,name}；创建独立设备并返回 client.json 内容 |
| GET | /api/device/profile | 设备凭据；获取最新配置与中转权限 |
| GET | /api/downloads | 已发布 ZIP 列表 |
| GET | /downloads/{file} | 客户端 ZIP |
| GET | /admin/accounts | X-Admin-Key；账号及套餐列表 |
| PUT | /admin/accounts/{id}/plan | X-Admin-Key；{plan:"basic"或"pro",expiresAt:ISO时间} |
| GET | /admin/audit | X-Admin-Key；最近审计事件 |
| GET | /admin/status | X-Admin-Key；协调实例、连接与中转计数 |
| GET | /internal/punch/snapshot | X-Node-Key=独立打洞密钥 |
| POST | /internal/relay/inspect | X-Node-Key=独立中转密钥；{token:设备凭据} |

加入成功配置含 deviceId、deviceToken、controlUrl、group、sharedSecret、dataSecret、
server、coordinatorServers、relayUrls 等字段。不同设备不能复制同一个 client.json；
否则它们会以同一个设备身份连接并替换已有连接。

错误：400 参数无效、401 未认证／无效凭据、403 没有中转权限、
404 资源不存在或不属于当前用户、409 配额或状态冲突、429 请求频率过高。


## v0.2.0 新增

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | /console /ops | 服务端校验会话；运营页要求管理员身份 |
| PUT | /api/networks/{id} | {name} 重命名网络 |
| PUT | /api/networks/{id}/groups/{groupId} | {name} 重命名分组 |
| PUT | /api/networks/{id}/devices/{deviceId} | {name} 重命名设备 |
| POST | /api/networks/{id}/devices/{deviceId}/configuration | 轮换设备凭据并返回新配置，旧配置失效 |
| GET / DELETE | /api/security/sessions | 列出有效会话 / 撤销除当前外所有会话 |
| POST | /api/security/password | {currentPassword,newPassword}，撤销所有登录会话 |
| POST | /api/security/recovery-key | {currentPassword,newPassword:""}，生成一次性返回的 recoveryCode |
| POST | /api/auth/recover | {email,recoveryCode,newPassword}，旧会话和恢复码失效，返回新的恢复码 |
| GET | /api/audit | 本账号最新 100 条审计 |
| GET / POST | /admin/nodes | 管理员；注册 {name,role,endpoint} 返回一次性 nodeKey |
| DELETE | /admin/nodes/{id} | 管理员撤销节点 |
| POST | /internal/node/heartbeat | X-Node-Key；{nodeId,role,version}，角色绑定校验 |

/admin 接口同时支持已认证管理员会话，不对普通账号开放。节点角色为 punch / relay；不允许互换权限。新注册节点需心跳后才进入下发列表。下载目录按文件名白名单提供版本、类型、平台、大小、SHA-256；支持 HTTP Range。

## v0.3.0 邮箱、网段与管理员接口

注册必须先 POST /api/auth/email-code {email}，再将收到的 verificationCode 与 email/password 一起提交 /api/register。验证码只通过邮箱发送；/api/registration 返回 emailVerificationRequired 与 mailReady，未配置发信时禁止请求新验证码。

| 方法 | 路径 | 内容 |
|---|---|---|
| GET | /admin/accounts/{id} | 账号资料、网络/分组、加入码状态、设备和审计；不返回密码或密钥原文 |
| GET | /admin/devices | 所有设备及主协调/独立节点的真实在线连接 |
| GET | /admin/networks | 所有用户的网络、网段、分组及设备数量 |
| PUT | /admin/accounts/{id}/status | {disabled}；停用普通用户，管理员不可通过此接口停用 |
| GET / PUT | /admin/mail | 读取/保存 SMTP、通知收件人和通知开关；查询只返回 passwordConfigured |
| POST | /admin/mail/test | {email} 向指定邮箱发送测试邮件，需先保存发信设置 |
| PUT | /api/networks/{id}/subnet | {name,subnet}；已有有效设备时拒绝更改 |
| GET | /install.cmd /install.ps1 /install.sh | 公开的一键安装入口，脚本不包含用户加入码或设备凭据 |

POST /api/networks 可带 subnet（例如 10.88.0.0/24），不填写自动选取未重叠的 /24；同账号的网络不能重叠，仅支持 RFC1918 私有 IPv4 CIDR /8–/30。网段的网络地址和广播地址不可分配，地址池不足返回 409。

/admin/mail 写入字段：enabled、host、port、security（ssl/starttls）、username、password、fromEmail、fromName、notificationEmail、notifyRegistrations、notifyMembershipChanges。password 留空保留旧值，更改主机或发信账号时要求重新提供。保存为 AES-GCM 密文，HTTP 查询不返回密文或明文。TLS 证书正常验证，不允许明文 SMTP。

节点心跳新增 deviceIds 数组，为该节点当前真实连接设备。仅有效节点凭据可上报；无效/已撤销设备不会计为在线。节点报告超过 45 秒不计入在线，节点自身健康下发窗口仍为 60 秒。历史 0.2.0 网络缺省迁移为原 10.77.0.0/16，已有设备身份和地址保持不变。

## v0.3.6 Android 安装

POST /api/networks/{id}/installations 使用已登录网络所有者权限，提交 {name,groupId,platform:"android"}。返回 id、expiresAt、joinUri、qrDataUrl；command 和 script 为空。二维码在服务端本地生成，不调用第三方二维码服务。票据在 edgevpn://join?server=<HTTPS平台地址>#<票据> 的 fragment 中，30 分钟有效。

Android 应用经用户确认后 POST /api/install/redeem，Authorization: Bearer <票据>，JSON 为 {claim,platform:"android"}；claim 为随机 32 字节的 Base64URL，稳定保存用于同机重试。同一票据不能绑定不同 claim，设备撤销后也不能复用。响应与桌面 ClientProfile 相同。

GET /api/device/profile 使用设备 Bearer token；账号禁用、设备撤销、网络或分组失效均拒绝认证。GET /api/downloads 中 Android 的 kind=client、platform=android，文件名 edge-vpn-client-android-版本.apk。下载接口提供 APK MIME 类型、SHA256 ETag 和 Range，计入运营下载统计。
