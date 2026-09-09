#!/bin/bash
# CNB Release 资产上传：用法 release_upload.sh <file>...
# 依赖环境：CNB_TOKEN（流水线内置令牌）、SITLENS_TAG（缺省取 git describe）
set -eu
REPO=${SITLENS_REPO:-feng-qiao/sitelens}
TAG=${SITLENS_TAG:-$(git describe --tags --exact-match 2>/dev/null || echo "$CNB_BRANCH")}
API="https://api.cnb.cool/$REPO"
AUTH="Authorization: Bearer $CNB_TOKEN"

RID=$(curl -sf -H "$AUTH" "$API/-/releases/tags/$TAG" | jq -r '.id // empty')
if [ -z "$RID" ]; then
  RID=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"tag_name\":\"$TAG\",\"name\":\"SiteLens $TAG\"}" "$API/-/releases" | jq -r '.id')
fi
[ -z "$RID" ] && { echo "release 创建失败"; exit 1; }

for f in "$@"; do
  NAME=$(basename "$f")
  SIZE=$(stat -c%s "$f")
  UP=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"asset_name\":\"$NAME\",\"size\":$SIZE}" "$API/-/releases/$RID/asset-upload-url" | jq -r '.upload_url')
  curl -sf -X PUT --data-binary @"$f" "$UP" >/dev/null
  echo "uploaded: $NAME"
done
