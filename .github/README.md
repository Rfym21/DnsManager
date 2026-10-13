# 编译与发布

[workflows/release.yml](workflows/release.yml) 使用仓库自带的 `GITHUB_TOKEN` 创建 GitHub Release 并推送 GitHub Container Registry（GHCR）镜像，无需 Docker Hub 账号或额外 Token。

## 触发与版本

- 自动：向 `main` 分支推送包含根目录 `VERSION` 变更的提交。
- 手动：在 **Actions → Build and Release → Run workflow** 选择分支。工作流先提交到默认分支，GitHub 才会显示手动入口。
- Pull Request 不会触发发布。

版本读取所选提交的 `VERSION`，支持 `2.21`、`2.21.1`、`v2.21` 和 `2.22-rc.1`；不支持 `+` 构建元数据。Release 标签统一为 `v<版本>`。新提交发布前应增加版本；已有标签若指向另一提交，工作流会在构建前失败。同一提交可以重新运行。

Go 二进制通过构建参数注入版本，运行 `dnsmgr version` 查看；包内 `VERSION` 保留原文件内容。含 `-rc.1`、`-beta.1` 等后缀的版本标记为预发布，不更新 `latest`。

## 检查与构建

发布前检查前端 ESLint、Vitest，Go vet、接口契约及 race 测试；数据库使用临时 SQLite 文件和隔离 MySQL 8.4／PostgreSQL 18 服务，不需要仓库凭据。

使用 Node 26 与 `web/package-lock.json` 安装依赖，前端只构建一次，直接输出到 `server/internal/webui/dist/`。Go 版本读取 `server/go.mod`，六个平台共用内嵌前端，以 `CGO_ENABLED=0` 构建。

| 系统 | 架构 | Release 资产 |
| --- | --- | --- |
| Linux | amd64、arm64 | `dnsmgr_<版本>_linux_<架构>.tar.gz` |
| macOS | amd64、arm64 | `dnsmgr_<版本>_darwin_<架构>.tar.gz` |
| Windows | amd64、arm64 | `dnsmgr_<版本>_windows_<架构>.zip` |

压缩包包含二进制、`VERSION`、`README.md`、`config.env.example`（来自 `server/.env.example`）和 `UPSTREAM_COMMIT`；仓库存在 `LICENSE`、`NOTICE`、`THIRD-PARTY-LICENSES.md` 时一并打包。Release 提供 SHA256 `checksums.txt` 和自动生成的发布说明，不打包运行数据或实际凭据。

容器任务通过 [docker/Dockerfile](docker/Dockerfile) 复用 Linux 发布包中的二进制，组装 `linux/amd64` 与 `linux/arm64` 镜像，不重复编译。根目录 `Dockerfile` 用于本地从源码完整构建。全部检查、六平台构建和镜像推送成功后才创建或更新 Release。

## 镜像与 GitHub 设置

镜像地址按当前仓库生成：`ghcr.io/<仓库所有者>/<仓库名>`，全部小写。镜像标签为 `<版本>`、`v<版本>`、`sha-<完整提交 SHA>`；默认分支的正式版本还更新 `latest`。

```sh
docker pull ghcr.io/<仓库所有者>/<仓库名>:2.21
```

仓库须启用 GitHub Actions，允许发布任务申请 `contents: write`、`packages: write`。首次推送后，若需要匿名拉取，在 **Packages → 对应包 → Package settings** 将可见性设为 **Public**；复用已有 GHCR 包时，须允许本仓库的 Actions 访问。
