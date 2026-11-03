#!/bin/bash
# CNB Release 资产上传：用法 release_upload.sh <file>...
# 依赖环境：CNB_TOKEN（流水线内置令牌）、SITLENS_TAG（缺省取 git describe）
#          SITLENS_BODY_FILE（可选：发行说明 markdown 文件；有它时版本页按本文件重建）
# 注意：所有 API 调用必须带 Accept: application/json（缺则 406）；
#       上传 PUT 成功后还须 POST verify_url 确认，资产才可见。
#
# 幂等策略（tag 重推 / 重跑流水线）：
#   - 带 SITLENS_BODY_FILE（安装包上传）：**删除旧 Release → 推回被级联删除的 tag →
#     用最新发行说明重建并设 latest → 上传资产**。CNB 的 PATCH 实测不生效，
#     重建是唯一能让发行说明与 latest 一起更新的路径（旧 Electron 流水线同款做法）。
#   - 不带 BODY（追加附件，如 Linux deb）：复用已有 Release，只上传资产（overwrite）。
set -eu
REPO=${SITLENS_REPO:-feng-qiao/sitelens}
TAG=${SITLENS_TAG:-$(git describe --tags --exact-match 2>/dev/null || echo "$CNB_BRANCH")}
API="https://api.cnb.cool/$REPO"
AUTH="Authorization: Bearer $CNB_TOKEN"
ACC="Accept: application/json"
GITURL="https://cnb:$CNB_TOKEN@cnb.cool/$REPO.git"

BODY_OK=0
BODY_SRC=""
if [ -n "${SITLENS_BODY_FILE:-}" ] && [ -f "$SITLENS_BODY_FILE" ]; then BODY_OK=1; BODY_SRC="$SITLENS_BODY_FILE"; fi

# 发行说明里的体积/SHA256 占位符用**本次实际上传的文件**回填（构建两次哈希必不同，
# 写死数值必然漂移）。占位符：__SIZE__ / __SHA256__（第一个附件=安装包）、
# __DEB_SIZE__ / __DEB_SHA256__（附件里的 .deb）。
if [ "$BODY_OK" = "1" ]; then
  BODY_TMP=/tmp/release-body-filled.md
  cp "$BODY_SRC" "$BODY_TMP"
  FIRST="${1:-}"
  if [ -n "$FIRST" ] && [ -f "$FIRST" ]; then
    FSIZE=$(stat -c%s "$FIRST")
    FSHA=$(sha256sum "$FIRST" | cut -d" " -f1 | tr "a-f" "A-F")
    sed -i "s/__SIZE__/$FSIZE/g; s/__SHA256__/$FSHA/g" "$BODY_TMP"
  fi
  for f in "$@"; do
    case "$f" in
      *.deb)
        DSIZE=$(stat -c%s "$f")
        DSHA=$(sha256sum "$f" | cut -d" " -f1)
        sed -i "s/__DEB_SIZE__/$DSIZE/g; s/__DEB_SHA256__/$DSHA/g" "$BODY_TMP"
        ;;
    esac
  done
  SITLENS_BODY_FILE="$BODY_TMP"
fi

RID=$(curl -sf -H "$AUTH" -H "$ACC" "$API/-/releases/tags/$TAG" | jq -r '.id // empty')
if [ -n "$RID" ] && [ "$BODY_OK" = "1" ]; then
  echo "release 已存在，按发行说明重建（$TAG）"
  curl -sf -X DELETE -H "$AUTH" -H "$ACC" "$API/-/releases/$RID" >/dev/null \
    || { echo "× 删除旧 release 失败"; exit 1; }
  # CNB 实测：删除 Release 会级联删除同名 git tag；重建前必须把 tag 推回，
  # 否则 release 无法关联版本。tag 指向本次构建提交（含最新修复）。
  git tag -f "$TAG" >/dev/null 2>&1 || true
  git push -f "$GITURL" "refs/tags/$TAG" >/dev/null 2>&1 \
    || echo "⚠ tag 推回失败（release 仍会创建，但版本页可能不显示 tag）"
  sleep 2
  RID=""
fi

if [ -z "$RID" ]; then
  if [ "$BODY_OK" = "1" ]; then
    # 发行说明随版本维护（docs/release-<ver>/release-body-<ver>.md），jq -Rs 自动转义
    jq -Rs --arg tag "$TAG" \
      '{tag_name:$tag, name:("SiteLens "+$tag), body:., make_latest:"true"}' \
      "$SITLENS_BODY_FILE" > /tmp/rel-create.json
    RID=$(curl -sf -X POST -H "$AUTH" -H "$ACC" -H "Content-Type: application/json" \
      --data-binary @/tmp/rel-create.json "$API/-/releases" | jq -r '.id')
    rm -f /tmp/rel-create.json
  else
    RID=$(curl -sf -X POST -H "$AUTH" -H "$ACC" -H "Content-Type: application/json" \
      -d "{\"tag_name\":\"$TAG\",\"name\":\"SiteLens $TAG\",\"make_latest\":\"true\"}" \
      "$API/-/releases" | jq -r '.id')
  fi
fi
[ -z "$RID" ] && { echo "release 创建失败"; exit 1; }

for f in "$@"; do
  NAME=$(basename "$f")
  SIZE=$(stat -c%s "$f")
  RESP=$(curl -sf -X POST -H "$AUTH" -H "$ACC" -H "Content-Type: application/json" \
    -d "{\"asset_name\":\"$NAME\",\"size\":$SIZE,\"overwrite\":true}" \
    "$API/-/releases/$RID/asset-upload-url")
  UP=$(echo "$RESP" | jq -r '.upload_url')
  VERIFY=$(echo "$RESP" | jq -r '.verify_url // empty')
  curl -sf -X PUT --data-binary @"$f" "$UP" >/dev/null
  if [ -n "$VERIFY" ]; then
    curl -sf -X POST -H "$AUTH" -H "$ACC" "$VERIFY" >/dev/null
  fi
  echo "uploaded: $NAME"
done
