# Release binaries already contain the frontend; reuse them for both architectures.
FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -g 10001 dnsmgr \
    && adduser -D -H -u 10001 -G dnsmgr dnsmgr \
    && mkdir -p /data /exports \
    && chown dnsmgr:dnsmgr /data /exports

ARG TARGETARCH
COPY --chmod=755 ${TARGETARCH}/dnsmgr /usr/local/bin/dnsmgr
USER 10001:10001
ENV LISTEN_ADDR=0.0.0.0:8080 STATE_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dnsmgr"]
CMD ["serve"]
