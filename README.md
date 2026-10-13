# DNS Manager · React + Go

面向自部署的 DNS、证书与自动化管理系统。新版采用 React 19 + TypeScript 和 Go，支持多用户、域名权限和旧 API 兼容。默认浅色，支持深色和系统主题；界面使用中性灰、细边框、编辑抽屉、命令面板、柔和光带和数据就绪后的退潮揭示。

本项目基于上游 [netcccyun/dnsmgr](https://github.com/netcccyun/dnsmgr.git) 的提交 [`b42dbcf88bccca287e9e9af53e87ba399a5ae295`](https://github.com/netcccyun/dnsmgr/commit/b42dbcf88bccca287e9e9af53e87ba399a5ae295) 修改。

已有实例的数据由用户自行手动迁移：在新实例中重新配置账户、权限与自动化任务，并通过界面导入 DNS 记录或证书。项目不提供读取旧数据库的迁移工具。

API 契约为 [server/openapi.json](server/openapi.json)（OpenAPI 3.1），前端生成类型为 [web/src/generated/contracts.ts](web/src/generated/contracts.ts)；生成与一致性检查命令见下方“验证”。

## 功能

- 多用户与逐域名读写权限、TOTP、可配置登录验证码、临时域名登录链接、Scoped PAT 和 CSRF。
- 22 个 DNS 平台原生适配器：记录 CRUD、线路、TTL、平台支持的状态／备注／权重／分组／别名／日志；分页及全量导出。
- JSON、CSV、TSV、BIND、XLS/XLSX 导入预览；智能解析、跨域名搜索与原域名内批量编辑。
- Cloudflare Custom Hostnames、Fallback Origin、DCV、TXT 目标、Tunnels、Ingress、CIDR/Hostname Routes 与 DNS 联动。
- ACME／云证书签发、DNS challenge/CNAME 委托、RSA/ECDSA、续签、吊销、PEM/PFX 导入导出和 50 个部署平台适配器。
- HTTP/TCP/ICMP 监控、主备与条件容灾、时区调度、IPv4/IPv6 优选 IP、域名及证书到期提醒。
- MySQL、PostgreSQL 或 SQLite 持久化任务、租约与 fencing、跨进程资源锁、逐项结果、SSE 日志、取消和人工核对后的恢复；通知 outbox。
- AES-GCM 加密凭据、私钥专用下载接口、审计与备份恢复。

未提供真实平台凭据的集成仍需要部署者联调；协议夹具、目录登记和编译成功不代替真实签发或部署。

## Docker Compose 启动

需要 Docker Engine、Compose v2 和 Python 3；首次构建需要访问依赖仓库。根目录 `Dockerfile` 先构建 React，再将前端资源嵌入 Go 二进制；运行镜像无需单独的前端目录。

```bash
python3 deploy/init-secrets.py
cp deploy/.env.example deploy/.env
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
```

访问 `http://localhost:18080`，使用本地 `deploy/secrets/setup_token` 中的安装令牌创建首个管理员。密码至少12个字符且不超过72字节。令牌应只在本机读取并填写到安装页。脚本拒绝覆盖已有 secrets；升级时保留整个目录。

默认端口仅绑定回环地址。公网部署通过反向代理提供 HTTPS，并将 `deploy/.env` 中 `PUBLIC_URL` 改为完整外部源地址，例如 `https://dns.example.com`。它决定来源校验、Secure Cookie 和回调链接。代理应转发到 API 的同源入口；任务事件流关闭代理缓冲并设置较长读取超时。

Compose 包含 MySQL 8.4、一次性 schema migration、API 和 Worker。API/Worker 使用 UID 10001、只读根文件系统和独立 `/data`、`/exports` 卷；没有 Redis 依赖。API 的 `/health/live` 检查进程，`/health/ready` 检查数据库；旧 `/dmtask/status` 检查 Worker 心跳。

平台账户、CA 和通知渠道均在界面填写。账户启用代理前，在“系统设置”配置默认代理；支持 HTTP/HTTPS/SOCKS4/4a/5/5h。本地证书部署需先把 `/exports` 加入允许目录，再配置证书和私钥输出路径。SSH 需填写验证过的主机密钥。通知和签发任务执行真实外部操作，任务中心显示实际结果。

## 本地开发

需要 Go 1.26.6+、Node 26 和 npm；数据库选择 MySQL 8.4、PostgreSQL 或 SQLite。SQLite 使用纯 Go 驱动，无需数据库服务或 C 编译器。精确依赖版本由 `server/go.mod` 与 `web/package-lock.json` 锁定。

必须设置 `DATABASE_DSN_FILE` 或 `DATABASE_DSN`，应用按 DSN 自动选择数据库。推荐将 DSN 存入权限为0600的私有文件，内容选择下面一项。MySQL 原有 DSN 格式保持兼容；MySQL/PostgreSQL 先创建仅供开发的数据库。

| 数据库 | DSN 文件内容示例 |
| --- | --- |
| MySQL | `dnsmgr:EXAMPLE_PASSWORD@tcp(127.0.0.1:3306)/dnsmgr_dev` |
| PostgreSQL | `postgres://dnsmgr:EXAMPLE_PASSWORD@127.0.0.1:5432/dnsmgr?sslmode=disable` |
| SQLite | `sqlite:/absolute/path/to/dnsmgr.db`；Windows：`sqlite:C:/path/to/dnsmgr.db` |

PostgreSQL 的 `sslmode=disable` 仅用于本机开发；生产连接使用 `sslmode=verify-full` 并配置可信 CA。不要使用生产数据库运行开发或集成测试。

SQLite 首次连接自动创建数据库文件并启用 WAL、外键、10秒锁等待和 `BEGIN IMMEDIATE` 写事务。API 与 Worker 必须使用同一个规范绝对路径，并对数据库、`-wal`／`-shm` 文件和相邻 `.locks/` 目录具有读写权限；`.locks/` 使用操作系统文件锁协调进程，运行中不要删除。SQLite 适用于单机本地磁盘，不支持网络文件系统或多主机扩展；多实例部署可选择 MySQL/PostgreSQL。无论使用哪种数据库，都须保留相同的 `STATE_DIR/master.key`。

从仓库根目录先构建前端，再运行 Go。`npm run build` 由 Vite 直接输出到忽略的 `server/internal/webui/dist/`，供 `go:embed` 编译；每次前端构建会清理该目录中的旧资源。首次运行任何 Go 构建、测试或合同命令前都需要此步骤。前端修改后重新构建二进制即可更新内嵌页面。

```bash
npm --prefix web ci
npm --prefix web run build
export DATABASE_DSN_FILE=/absolute/path/to/database-dsn
export STATE_DIR=/absolute/path/to/private-state
export LISTEN_ADDR=127.0.0.1:18081
export PUBLIC_URL=http://127.0.0.1:5173
cd server
go run ./cmd/dnsmgr migrate
go run ./cmd/dnsmgr serve
```

`migrate` 仅初始化或升级本应用的数据库表结构，不导入旧实例数据。

另开终端，在 `server/` 使用相同数据库和状态目录运行 `go run ./cmd/dnsmgr worker`。前端在仓库根目录运行：

```bash
npm --prefix web run dev
```

Vite 默认代理到 `127.0.0.1:18081`；可用 `DNSMGR_API_TARGET` 覆盖。Go 不自动读取 `.env`，按 [server/.env.example](server/.env.example) 导出环境变量。直接访问 Go 内嵌前端时，把 `PUBLIC_URL` 改为该服务的实际地址。运行已编译二进制无需 Node、单独的前端资源目录或 `WEB_DIR`。

## 验证

```bash
npm --prefix web ci
npm --prefix web run lint
npm --prefix web test
npm --prefix web run build
cd server
go build ./cmd/dnsmgr
go vet ./...
go test -race -p 1 ./...
go run ./cmd/contracts --check
```

`go test -race ./internal/httpapi -run 'TestEmbeddedFrontend'` 验证内嵌首页、SPA 深层路由、静态资源与不存在资源的响应，不需要数据库。race 检查需要可用的 C 编译器；SQLite 表结构、存储和备份测试自动使用临时数据库文件，未配置隔离服务端数据库时，对应集成测试会跳过。

前端单元与组件检查使用 Vitest 和 Testing Library，由 `npm --prefix web test` 执行。修改页面后，在本地隔离实例手动检查登录、路由刷新、表单错误、浅／深主题、移动布局、键盘操作和浏览器控制台。

生成接口合同在 `server/` 使用 `go run ./cmd/contracts --write`，同步更新 OpenAPI 与前端生成类型；`go run ./cmd/contracts --check` 验证实际路由、Go 模型和 TypeScript 产物，合同 race 检查使用 `go test -race ./internal/contracts`。

应用集成和备份全表恢复测试使用专用隔离数据库：

```bash
# 以下命令从 server/ 运行，且已完成前端构建。
TEST_DATABASE_DSN_FILE=/path/to/isolated-dsn go test -race -p 1 ./internal/...
TEST_POSTGRES_DATABASE_DSN_FILE=/path/to/isolated-postgres-dsn \
go test -race -p 1 ./internal/store
BACKUP_TEST_SOURCE_DSN_FILE=/path/to/source-test-dsn \
BACKUP_TEST_TARGET_DSN_FILE=/path/to/target-test-dsn \
go test -race -p 1 ./internal/backup
BACKUP_CLI_SOURCE_DSN_FILE=/path/to/source-test-dsn \
BACKUP_CLI_TARGET_DSN_FILE=/path/to/target-test-dsn \
go test -race -p 1 ./cmd/dnsmgr -run '^TestBackupRestoreCLI$'
```

数据库集成会写入并删除夹具，请串行运行包（`-p 1`）。PostgreSQL 存储测试在专用测试数据库内创建独立临时 schema，测试账户需要创建 schema 的权限。真实 API/Worker/Compose 检查的步骤与前提见 [隔离实例验收](deploy/checks/README.md)。

## 发布包

GitHub Actions 在 `main` 分支的 `VERSION` 变更时自动发布，也可手动运行 **Build and Release**。版本支持 `2.21`、`2.21.1`、`2.22-rc.1` 等格式；同一版本的标签不能改指向另一提交。配置与权限说明见 [.github/README.md](.github/README.md)。

发布前执行前端 lint／单元测试、Go 静态检查、接口契约检查及 SQLite、MySQL、PostgreSQL 隔离测试；前端只构建一次，各平台二进制共用内嵌资源。GitHub Release 提供 Linux、macOS、Windows 的 amd64／arm64 包及 `checksums.txt`：

- Linux／macOS：`dnsmgr_<版本>_<系统>_<架构>.tar.gz`，macOS 系统名为 `darwin`。
- Windows：`dnsmgr_<版本>_windows_<架构>.zip`。
- 包内包含二进制、`VERSION`、本 README、`config.env.example` 和 `UPSTREAM_COMMIT`；配置示例不包含实际凭据。运行无需 Node 或单独的前端目录。

下载所需压缩包与 `checksums.txt` 后，使用 GNU `sha256sum` 验证已下载文件：

```bash
sha256sum --ignore-missing -c checksums.txt
```

解压后按 `config.env.example` 设置环境变量，再运行 `dnsmgr migrate`、`dnsmgr serve` 和 `dnsmgr worker`；Windows 使用 `dnsmgr.exe`。Go 不自动加载该配置文件。`dnsmgr version` 显示构建时的版本。

双架构容器镜像发布到 `ghcr.io/<仓库所有者>/<仓库名>`（小写），直接复用 Linux 发布包中的二进制。可使用 `<版本>`、`v<版本>`、`sha-<提交 SHA>` 标签；`latest` 仅在默认分支的正式版本更新。

## 升级与恢复

升级前停止写入和 Worker，保存数据库及 `/data/master.key`，再构建新镜像并运行 `dnsmgr migrate` 升级本应用的表结构。密钥丢失将无法解密凭据。`docker compose down` 保留卷；带 `-v` 会删除数据卷，不用于常规升级。

Go 完整备份示例（先停止 API 和 Worker）：

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml stop api worker
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm --no-deps api backup --archive /data/backup.enc --go-frozen
```

备份归档不包含主密钥；另行安全保存 `master.key`、Compose secrets 与 `/exports`。恢复要求**相同数据库引擎、匹配的表结构、相同主密钥，以及已初始化但没有应用数据的目标数据库**，执行 `restore --archive /data/backup.enc --go-frozen --dry-run` 后再正式恢复。未记录数据库引擎的旧归档按 MySQL 处理；不支持通过备份跨引擎转换数据。SQLite 使用应用备份命令时也须停止 API/Worker，不要只复制仍在写入的 `.db` 文件。恢复不会回滚远端 DNS、CA 或云部署的实际状态，需核对远端。

本地恢复账户：`dnsmgr recover totp USERNAME`；恢复密码需 `RECOVERY_PASSWORD_FILE=/private/password-file dnsmgr recover password USERNAME`。密码文件必须0600，命令会撤销该用户的会话与 PAT，并写审计。

## 目录

| 目录 | 用途 |
| --- | --- |
| `web/` | React 页面、组件、主题／加载、Vitest 与 Testing Library |
| `server/` | Go HTTP API、适配器、自动化 Worker、备份恢复与数据库表结构升级 |
| `deploy/` | Compose、secret 初始化、隔离实例验收与发布打包 |

许可证沿用仓库 [LICENSE](LICENSE)。
