#!/bin/bash
# CNB Release 资产「按名替换」：先删同名旧资产，再走 release_upload.sh 上传。
# 用法 release_replace.sh <tag> <file>...
# 依赖环境：CNB_TOKEN（流水线内置令牌，需 repo-release:rw）
# 为什么不用 release_upload.sh 直接传：CNB 同名资产的重传语义不确定，
# 直接上传可能留下重名条目污染下载页与更新源；先删后传语义确定。
set -eu
REPO=${SITLENS_REPO:-feng-qiao/sitelens}
TAG=${1:?用法: release_replace.sh <tag> <file>...}
shift
API="https://api.cnb.cool/$REPO"
AUTH="Authorization: Bearer $CNB_TOKEN"
ACC="Accept: application/json"

RID=$(curl -sf -H "$AUTH" -H "$ACC" "$API/-/releases/tags/$TAG" | jq -r '.id // empty')
if [ -z "$RID" ]; then
  # 发行版不存在：带发行说明创建（有 SITLENS_BODY_FILE 时）
  if [ -n "${SITLENS_BODY_FILE:-}" ] && [ -f "$SITLENS_BODY_FILE" ]; then
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
  AID=$(curl -sf -H "$AUTH" -H "$ACC" "$API/-/releases/tags/$TAG" \
    | jq -r --arg n "$NAME" '.assets[] | select(.name==$n) | .id // empty')
  if [ -n "$AID" ]; then
    if curl -sf -X DELETE -H "$AUTH" -H "$ACC" "$API/-/releases/$RID/assets/$AID" >/dev/null; then
      echo "replacing: $NAME"
    else
      echo "WARN: 旧资产删除失败（继续上传）: $NAME"
    fi
  fi
  SITLENS_TAG="$TAG" bash "$(dirname "$0")/release_upload.sh" "$f"
done
