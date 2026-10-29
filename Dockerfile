# SiteLens Go 版镜像（多阶段构建，scratch 运行时——零基础镜像、零运行时依赖）
# 构建：docker build -t sitelens .
# 运行：docker run --rm -p 5000:5000 -v sitelens-state:/app/data/state sitelens
#
# 说明：
#   - CGO_ENABLED=0 静态编译，scratch 运行时仅需 CA 证书（出站 HTTPS 探测用）；
#     容器内因此**没有 AST 污点分析能力**（需 CGO，属已知降级，见交接文档 §2.3）
#   - 扫描目标请勿写 localhost（容器内 localhost 指容器自身）
#   - 数据资产分层（5.2 起，BUG-020）：
#       随镜像：指纹库 data/go、受影响区间、字典、**情报库/CVE 字典/模板情报**
#               （后三者体量小，随镜像避免"情报关联/KEV/CVSS 补全/模板情报静默降级"）
#       不随镜像：模板池（解包后 ~700MB）与 ML 模型资产（~750MB）——体量原因
#               不进镜像，需挂载或用对应 update-* 子命令拉取到用户区：
#                 模板池：-v <host>/nuclei:/app/data/nuclei
#                         （或容器内 `sitelens update-nuclei` / `update-afrog`）
#                 ML 资产：-v <host>/ml_assets:/app/models/go/ml_assets
#                         （引擎候选路径：data/go/ml_assets → models/go/ml_assets）
#       想确认本容器的资产就位矩阵：`GET /api/diagnostics`（反馈页同源数据，
#       逐项标注就位/缺失以及缺失会让哪项能力静默降级）
#   - data/state 是 VOLUME：镜像内往该目录放内容会被匿名卷遮蔽，故 KEV 增量
#     （state/kev_extra.json）不预置——首次运行按 intel.update_hours 自动更新

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
# 情报类资产（BUG-020）：缺失时情报关联/KEV 标记/CVSS 补全/模板情报会**静默降级**，
# 体量可接受，统一随镜像交付
COPY --from=build /src/data/intel_dump.json.gz /app/data/intel_dump.json.gz
COPY --from=build /src/data/nvd_cves.json.gz /app/data/nvd_cves.json.gz
COPY --from=build /src/data/tpl_intel.json.gz /app/data/tpl_intel.json.gz
# CA 证书（出站 HTTPS 探测）
COPY --from=build /out/rt/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# 非 root 运行
USER 65532:65532
EXPOSE 5000
VOLUME ["/app/data/state"]
ENTRYPOINT ["/app/sitelens"]
CMD ["serve"]
