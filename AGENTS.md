# Repository Guidelines

## Project Structure & Module Organization

- `web/src/`: React + TypeScript pages, components, styles, and API transport; entry: `main.tsx`. Tests are colocated with source.
- `server/cmd/dnsmgr/`: Go API, worker, migration, backup, and recovery CLI. `server/internal/` contains HTTP handlers, providers, automation, and SQL persistence.
- `server/migrations/`: embedded goose SQL migrations. Add migrations rather than editing applied files.
- `deploy/`: Compose, packaging, and isolated acceptance checks. `docs/migration-runbook.md`: existing-instance migration and recovery procedures.

Vite builds directly into ignored `server/internal/webui/dist/`, clearing old assets; `go:embed` includes them in the executable. Runtime needs no frontend directory.

## Build, Test, and Development Commands

Use Node 26, Go 1.26.6+, and isolated MySQL 8.4. Follow `README.md` and `server/.env.example` for environment setup; Go does not load dotenv files.

- From `web/`, `npm ci` installs dependencies; `npm run dev` starts Vite.
- From `web/`, `npm run build` checks TypeScript and prepares embedded assets. Run it before Go commands; rebuild after frontend edits. `npm run lint` runs ESLint; `npm test` runs Vitest.
- From `server/`, `go build ./cmd/dnsmgr` builds the CLI. Run `go run ./cmd/dnsmgr migrate`, then `serve` and `worker` in separate terminals.
- From `server/`, `go vet ./...` and `go test -race -p 1 ./...` check Go code.
- From `server/`, `go run ./cmd/contracts --write` regenerates contracts; `--check` verifies them.

## Coding Style & Naming Conventions

Inspect files immediately before editing; preserve unrelated work. Format Go with `gofmt`/`goimports` (tabs); match nearby TypeScript indentation. Use PascalCase for React components. Exported Go symbols need godoc comments; wrap errors with `%w`. Reuse semantic classes and CSS variables in `web/src/styles.css`. Preserve CSRF, scoped authority, secret redaction, resource locks, and lease fencing.

## Testing Guidelines

Use `*_test.go` and colocated `*.test.ts(x)`; cover meaningful behavior with Go tests, Vitest, and Testing Library. From `server/`, `go test -race ./internal/httpapi -run 'TestEmbeddedFrontend'` checks embedded assets without a database. Manually smoke-test changed pages, route refresh, themes, mobile layouts, and keyboard access; inspect console errors. Database tests require isolated `_DSN_FILE` fixtures and serial execution (`-p 1`). Run `git diff --check`.

## Commit & Pull Request Guidelines

No commit history or PR template exists. Use imperative subjects. PRs should explain changes, link issues, report checks and prerequisites, and include screenshots for visible UI changes.

## Security & Configuration

Never commit credentials or private keys. Supply database connections through 0600-permission `DATABASE_DSN_FILE` files. Retain `STATE_DIR/master.key` alongside backups; backup archives exclude it. Never run integration checks against production databases or real domains.
