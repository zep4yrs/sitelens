# SiteLens Go 版镜像（多阶段构建，scratch 运行时——零基础镜像、零运行时依赖）
# 构建：docker build -t sitelens .
# 运行：docker run --rm -p 5000:5000 -v sitelens-state:/app/data/state sitelens
# 说明：
#   - CGO_ENABLED=0 静态编译，scratch 运行时仅需 CA 证书（出站 HTTPS 探测用）
#   - 扫描目标请勿写 localhost（容器内 localhost 指容器自身）
#   - intel_dump.json.gz 为可选数据：挂载到 /app/data/intel_dump.json.gz 启用情报关联

FROM golang:1.26-alpine AS build
WORKDIR /src
# 依赖 vendor 化：离线可构建（零运行时下载）
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
COPY data ./data
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w"     -o /out/sitelens ./cmd/sitelens
# CA 证书供出站 HTTPS（netsec/KEV/扫描）使用；alpine 基础镜像自带
RUN mkdir -p /out/rt/etc/ssl/certs &&     cp /etc/ssl/certs/ca-certificates.crt /out/rt/etc/ssl/certs/

FROM scratch
WORKDIR /app
COPY --from=build /out/sitelens /app/sitelens
# 运行数据：指纹库（必需）、区间/字典（可选，缺失自动降级）
COPY --from=build /src/data/go /app/data/go
COPY --from=build /src/data/affected_ranges.json /app/data/affected_ranges.json
COPY --from=build /src/data/wordlists /app/data/wordlists
# CA 证书（出站 HTTPS 探测）
COPY --from=build /out/rt/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# 非 root 运行
USER 65532:65532
EXPOSE 5000
VOLUME ["/app/data/state"]
ENTRYPOINT ["/app/sitelens"]
CMD ["serve"]
