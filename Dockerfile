FROM node:26-alpine AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.6-alpine AS backend
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
COPY VERSION /src/VERSION
COPY --from=frontend /src/server/internal/webui/dist ./internal/webui/dist
RUN version="$(tr -d '[:space:]' < /src/VERSION)" \
    && test -n "$version" \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$version" -o /out/dnsmgr ./cmd/dnsmgr

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -g 10001 dnsmgr \
    && adduser -D -H -u 10001 -G dnsmgr dnsmgr \
    && mkdir -p /data /exports \
    && chown dnsmgr:dnsmgr /data /exports
COPY --from=backend /out/dnsmgr /usr/local/bin/dnsmgr
USER 10001:10001
ENV LISTEN_ADDR=0.0.0.0:8080 STATE_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dnsmgr"]
CMD ["serve"]
