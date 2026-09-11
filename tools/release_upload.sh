#!/bin/bash
# CNB Release 资产上传：用法 release_upload.sh <file>...
# 依赖环境：CNB_TOKEN（流水线内置令牌）、SITLENS_TAG（缺省取 git describe）
#          SITLENS_BODY_FILE（可选：发行说明 markdown 文件，创建发行版时写入）
# 注意：所有 API 调用必须带 Accept: application/json（缺则 406）；
#       上传 PUT 成功后还须 POST verify_url 确认，资产才可见。
set -eu
REPO=${SITLENS_REPO:-feng-qiao/sitelens}
TAG=${SITLENS_TAG:-$(git describe --tags --exact-match 2>/dev/null || echo "$CNB_BRANCH")}
API="https://api.cnb.cool/$REPO"
AUTH="Authorization: Bearer $CNB_TOKEN"
ACC="Accept: application/json"

RID=$(curl -sf -H "$AUTH" -H "$ACC" "$API/-/releases/tags/$TAG" | jq -r '.id // empty')
if [ -z "$RID" ]; then
  CREATE="$API/-/releases"
  if [ -n "${SITLENS_BODY_FILE:-}" ] && [ -f "$SITLENS_BODY_FILE" ]; then
    # 发行说明随版本维护（tools/release-body-*.md），jq -Rs 自动转义
    jq -Rs --arg tag "$TAG" '{tag_name:$tag, name:("SiteLens "+$tag), body:.}' \
      "$SITLENS_BODY_FILE" > /tmp/rel-create.json
    RID=$(curl -sf -X POST -H "$AUTH" -H "$ACC" -H "Content-Type: application/json" \
      --data-binary @/tmp/rel-create.json "$API/-/releases" | jq -r '.id')
    rm -f /tmp/rel-create.json
  else
    RID=$(curl -sf -X POST -H "$AUTH" -H "$ACC" -H "Content-Type: application/json" \
      -d "{\"tag_name\":\"$TAG\",\"name\":\"SiteLens $TAG\"}" "$API/-/releases" | jq -r '.id')
  fi
fi
[ -z "$RID" ] && { echo "release 创建失败"; exit 1; }

for f in "$@"; do
  NAME=$(basename "$f")
  SIZE=$(stat -c%s "$f")
  RESP=$(curl -sf -X POST -H "$AUTH" -H "$ACC" -H "Content-Type: application/json" \
    -d "{\"asset_name\":\"$NAME\",\"size\":$SIZE}" "$API/-/releases/$RID/asset-upload-url")
  UP=$(echo "$RESP" | jq -r '.upload_url')
  VERIFY=$(echo "$RESP" | jq -r '.verify_url // empty')
  curl -sf -X PUT --data-binary @"$f" "$UP" >/dev/null
  if [ -n "$VERIFY" ]; then
    curl -sf -X POST -H "$AUTH" -H "$ACC" "$VERIFY" >/dev/null
  fi
  echo "uploaded: $NAME"
done
