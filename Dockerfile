# SiteLens Go 版镜像（多阶段构建）
# 构建：docker build -t sitelens .
# 运行：docker run --rm -p 5000:5000 -v sitelens-state:/app/data/state sitelens
# 说明：镜像内仅含二进制与数据文件；扫描目标请勿写 localhost
#（容器内 localhost 指容器自身，需用宿主机地址或 --network host）。

FROM golang:1.26-alpine AS build
WORKDIR /src
# 依赖 vendor 化：离线可构建（零运行时下载）
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
COPY data ./data
# CGO=0：纯静态二进制，可在 distroless 中直接运行
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/sitelens ./cmd/sitelens

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/sitelens /app/sitelens
# 运行所需数据文件（指纹库/知识库/字典；intel_dump 为可选降级项）
COPY --from=build /src/data/go /app/data/go
COPY --from=build /src/data/affected_ranges.json /app/data/affected_ranges.json
COPY --from=build /src/data/wordlists /app/data/wordlists
USER nonroot:nonroot
EXPOSE 5000
VOLUME ["/app/data/state"]
ENTRYPOINT ["/app/sitelens"]
CMD ["serve"]
