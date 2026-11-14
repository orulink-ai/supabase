# 账户绑定 v3：上线与回滚边界

状态：CN 与 GLOBAL 均已在新备份、隔离恢复及真实快照迁移演练后执行 v3 迁移，原账户与已有连接凭据保留；两区 Android／ESP32／Windows 的配网、换账号撤权及连接真机验收已通过，范围与缺口见文末验收报告。

## 服务合同

| 调用 | 身份 | 结果 |
|---|---|---|
| prepare_account_device_claim_v3 | authenticated | 本区域、已登记硬件的短期票据 |
| stage_account_device_claim_v3 | anon + 设备 HMAC | 保存设备已持久化的候选连接密钥 |
| commit_account_device_claim_v3 | authenticated | 预留 activation version；设备 ACK 前保持旧绑定并返回 false |
| account_device_claim_state_v3 | anon + 票据 | 不暴露密钥的签名 activation 回执 |
| ack_account_device_claim_v3 | anon + 设备 HMAC | 同一事务替换绑定、写凭据历史、更新 epoch 和 ACK |
| list_account_devices / get_account_device_link | authenticated + 当前 owner | 当前设备、版本及连接授权 |
| bootstrap_account_device_v3 | anon + 设备 HMAC | 证明已有旧密钥，返回签名版本；不改变 owner，不返回密钥 |
| account_device_status_v3 | anon + 随机区域挑战 | 设备验证用 active/revoked 签名；不返回密钥或 owner |

ACK 和 commit 使用相同事务锁顺序；唯一约束同时限制一个 owner 一个设备，以及一个设备一个 owner。设备/owner epoch 阻止旧候选覆盖新绑定。重复成功 ACK 和 commit 幂等，已被替代的旧请求失败关闭。

credential_history 不关联 owner 外键，迁移时回填已有绑定，后续 ACK 同事务写入。删除账户和替换绑定后仍能签发旧凭据撤销回执。该历史表、硬件验证根和 claims 均启用 RLS 且不向客户端授予表权限；历史密钥不可通过公共 RPC 读取。清理历史前必须有替代撤销方案，不能按账户删除级联清空。

## 部署顺序

1. 分别核对 CN/GLOBAL 运行版本、现有 schema 与绑定冲突；保留私有数据库/config 备份并做隔离恢复验证。新迁移遇到多 owner/device 冲突会停止，不自行删除数据。
2. 按文件顺序应用尚未执行的迁移。已存在的基线按实际 schema 核对，不盲目覆盖。记录执行文件及 SHA256；迁移事务失败应停止。
3. 管理员在私有 deployment 表明确写入唯一 CN 或 GLOBAL 区域。未配置时认领失败关闭。
4. 通过可信工厂路径登记每台设备的独立区域验证根，并与设备 NVS 中实际 WR 身份和根核对；禁止向 App 或二维码发布根。管理导入参数、SQL 文件和备份必须留在受限私有位置，不提交 Git。
5. 配套升级固件和 App/桌面端，执行新设备、同设备换账号、同账号换设备、掉电、旧会话撤销与离线 LAN 真机验收，再更新上线状态。

旧不安全的 claim_account_device 和 v2 prepare/stage/commit 权限在 v3 迁移中撤销。账户登录和原有绑定记录保留；旧固件不具备新设备侧撤销能力，不能宣称仅部署 SQL 就已完成安全换绑。

迁移包含授权合同变化。回滚应用版本不能自动恢复旧认领 RPC 的权限；不要以重新开放旧接口作为故障恢复。数据库回滚须使用已验证的私有备份，并评估迁移后新数据，避免覆盖用户新记录。

## 隔离验证

Windows 使用 scripts/test-bindings.ps1；macOS/Linux 使用 scripts/test-bindings.sh，二者委托 tests/run_sql_tests.py，语义和退出码一致。

测试只创建带专用标签、--network none、tmpfs 数据目录的 PostgreSQL 容器，不接触生产。覆盖旧绑定迁移、候选失败保留旧绑定、设备持久化 ACK 前不发布新绑定、换设备/换 owner、幂等与旧 epoch 拒绝、密钥隐私、旧接口禁用、账户删除后撤销，以及两个独立数据库会话竞争 ACK 时只允许一方成功。

## 当前部署与验收（2026-11-14）

国内与香港均在新备份、隔离恢复及迁移演练后应用四份迁移，最后为 `202611140002_claim_recovery.sql`，保留原 Auth 用户。002 将 stage/state/ACK 的竞争串行化，允许候选中止的签名恢复，并保持已撤销授权不可恢复。001 为已有历史，不改写已部署迁移。

Android／ESP32／Windows 两区真实配网、换 owner、旧凭据拒绝和新凭据连接通过；详见 [端到端验收](account-e2e-2026-11-14.zh-CN.md)。iOS／macOS 原生及两台实体机器人切换仍需补测。credential_history 和硬件 roots 不随临时测试账号清理，避免丢失旧凭据撤销证明。
