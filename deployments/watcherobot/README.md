# WatcheRobot 区域账户部署

此目录是组织内 WatcheRobot 自托管 Supabase 的部署配置来源，基于本仓库固定版本的
`docker/`，不修改 Supabase Auth 或 Postgres 上游源码。首次国内部署使用上游
`64fad1a785ca966c2d6aa8b2f3ce41f06ffdf4d4` 的镜像组合（包括 Postgres 17）；不能将这个新建环境的流程直接用于已有 Postgres 15 数据卷升级。

| 区域   | 数据位置         | 项目与账户                                 |
| ------ | ---------------- | ------------------------------------------ |
| cn     | 火山引擎中国大陆 | WatcheRobot CN，新建独立数据库、密钥及备份 |
| global | AWS 香港         | 保留现有项目与用户，升级需单独检查现网版本 |

两个区域不复制用户密码、会话、数据库卷或 JWT 签名密钥。国内默认公开入口为
`https://supabase.erroright.cn`，国际现有入口保持不变。`.env.example` 仅说明覆盖字段，不包含生产秘密。

## 环境与首次初始化

需要 Python 3.9+、Docker、Docker Compose 2.24.4+、HTTPS 反向代理，以及可用的 SMTP。
在部署前检查内存、磁盘、现有端口和原有站点。所有部署使用独立的 Compose 项目名与容器名。

1. 从已测试的功能分支 SHA 部署本仓库，至少包含 `docker/` 和 `deployments/watcherobot/`。
2. 在服务器私有目录复制 `docker/.env.example` 为环境文件。先在私有工作目录使用上游
   `docker/utils/generate-keys.sh` 和 `add-new-auth-keys.sh` 生成该项目自己的密钥；这些命令会输出密钥，必须重定向到权限 0600 的私有日志，不能粘贴到工单或 CI 输出。
3. 合并本目录 `.env.example` 中的字段，填入 SMTP 密码并设置 `chmod 600`。生成密钥时的临时 `.env` 也只能私有保存。
4. 使用 `nginx.conf.example` 新建独立子域名站点。先启用 HTTP ACME 路径，申请证书后再启用 TLS 块；执行 `nginx -t` 成功后 reload。保留原有站点、映射和证书。
5. 检查合并配置，再启动服务。

Windows PowerShell：

```powershell
./deployments/watcherobot/scripts/deploy.ps1 validate --region cn --env-file C:/private/watcherobot-cn.env
./deployments/watcherobot/scripts/deploy.ps1 up --region cn --env-file C:/private/watcherobot-cn.env
./deployments/watcherobot/scripts/deploy.ps1 status --region cn --env-file C:/private/watcherobot-cn.env
```

macOS/Linux：

```sh
sh deployments/watcherobot/scripts/deploy.sh validate --region cn --env-file /opt/watcherobot-cn/private/cn.env
sh deployments/watcherobot/scripts/deploy.sh up --region cn --env-file /opt/watcherobot-cn/private/cn.env
sh deployments/watcherobot/scripts/deploy.sh status --region cn --env-file /opt/watcherobot-cn/private/cn.env
```

两个入口委托同一 Python 核心，参数、默认区域和退出码相同。公共命令也可直接使用
`python deployments/watcherobot/scripts/deploy.py`；不执行任何 shell 拼接。配置不合格或命令失败返回非零。
`up` 创建/更新服务并等待健康检查；本工具不提供清空数据卷或自动恢复覆盖命令。

## 端口、账户和邮件

- API Gateway 只发布 `127.0.0.1:18200`，公网仅经 HTTPS 代理；数据库、连接池和邮件模板不发布宿主机端口。
- Studio 由官方 Gateway 的 Dashboard 用户名/密码认证保护；公网客户端的 Auth、REST 路径不附加 Dashboard Basic Auth。不得使用默认后台密码。
- 使用独立的 `POSTGRES_PASSWORD`、JWT 密钥、匿名/服务密钥和 opaque keys，客户端只允许持有公开 publishable key。
- 注册必须验证邮件；验证码有效期 900 秒、单用户最小重发间隔 60 秒、密码至少 8 位。模板中的 `{{ .Token }}` 为数字验证码。
- SMTP 默认 `smtp.feishu.cn:587`、发件地址 `hello@orulink.ai`，密码仅私有注入；不同区域共享同邮箱发信额度，需按实际流量限制总量。
- 暂不启用手机号或匿名注册。新增账户不等于设备绑定已经实现；后续业务迁移单独提交。
- 容器日志设为每文件 10 MB、最多 3 份。证书由 ACME 定期续签，续签后 reload Nginx。

国内主机现有透明代理曾导致 ACME HTTPS 失败。仅在该部署主机通过以下命令续签：

```sh
sh deployments/watcherobot/scripts/deploy.sh renew-certificate --region cn --env-file /opt/watcherobot-cn/private/cn.env --acme-home /root/.acme.sh
```

该操作需要 Linux root，仅在执行期间对 Let's Encrypt CA 当前解析出的公网 IPv4 的
TCP 443 添加直接出口规则，并在成功、失败或超时后删除同一规则，不调整原有代理链。
部署时安排每日执行，检查新证书是否安装和 Nginx reload；本机 Windows 入口可显示同样的参数，实际续签只能在部署主机执行。
如果 DNS 返回非公网地址或无法清理临时规则，命令失败，不当成续签成功。

## 备份与恢复验证

```sh
sh deployments/watcherobot/scripts/deploy.sh backup --region cn --env-file /opt/watcherobot-cn/private/cn.env --backup-file /opt/watcherobot-cn/backups/unique-timestamp.sql
```

PowerShell 使用相同参数调用 `deploy.ps1`。备份包含数据库角色及 Auth 数据，按秘密管理；文件私有创建，`pg_dumpall` 成功后才发布，拒绝覆盖已有备份。
正式上线需安排每日备份、独立存储副本与保留策略，并在一次性实例验证恢复；不得把生产恢复命令直接指向当前数据卷。
`--backup-dir` 可替代 `--backup-file`，每次生成带 UTC 时间及随机后缀的新文件，适合定时任务。
`crontab.example` 提供每日备份与证书检查的两条任务，替换区域及部署目录后安装到 root crontab；
按标记追加并保留原任务，不覆盖整份 crontab。不自动删除历史备份或替代独立存储副本。
上传对象存储的用户文件不在此 SQL 备份范围，首期账户服务不启用用户文件产品功能。

升级前备份环境文件、镜像清单、SQL 和代理配置；固定已验证 Git SHA。容器可退回兼容镜像，数据库不可假定任意降级；涉及破坏性迁移需单独恢复方案。

## 验证与开发流程

```sh
python -m unittest discover -s deployments/watcherobot/tests -v
```

测试覆盖区域/HTTPS 配置、默认秘密、公开数据库端口、邮件策略、固定镜像、参数安全及备份失败清理。
还必须在真实 Compose 合并结果执行 `validate`，不能只看 override 文件。部署验收检查服务健康、TLS、Dashboard 保护、REST 权限，以及注册/找回邮件实际送达。

代码、SQL、模板或部署配置改动进入 `codex/` 功能分支并通过 gh 创建 PR。
创建云项目、DNS/证书和实际执行部署不另外建立 PR，但在开发档案中记录部署 SHA、版本和验证依据；不自动合并。

同一 checkout 的上游 bind mount 目录只允许属于一个区域；首次启动会写入忽略目录中的区域标记，后续误用另一地区环境会被拒绝。两区必须使用独立 checkout 和数据卷，不能只改 Compose 项目名。

opaque API keys 依赖四项 asymmetric/JWKS 配置，已在 override 显式开启并校验；密钥生成脚本即使修改过上游 base compose，也不应依赖这些未入库改动。部署时保留或还原固定基线的 base 文件，配置来源以此目录为准。

Windows SQL 备份先移除继承权限、仅给文件所有者完全控制，再运行 pg_dumpall；权限设置失败会停止，不写入数据库内容。Linux 文件使用 0600。
