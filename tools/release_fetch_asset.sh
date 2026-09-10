#!/bin/bash
# CNB Release 资产下载：用法 release_fetch_asset.sh <tag> <asset_name> <dest_file>
# 依赖环境：CNB_TOKEN（对本仓库 Release 资产的读权限）、jq
# 用途：full 版 CI 构建从本仓库私有 Release 资产取回情报库（intel_dump 不入 git）
set -eu
REPO=${SITLENS_REPO:-feng-qiao/sitelens}
TAG=$1
NAME=$2
DEST=$3
API="https://api.cnb.cool/$REPO"
AUTH="Authorization: Bearer $CNB_TOKEN"

URL=$(curl -sf -H "$AUTH" -H "Accept: application/json" "$API/-/releases/tags/$TAG" \
  | jq -r --arg n "$NAME" '(.assets // [])[] | select(.name == $n) | .url // empty')

[ -n "$URL" ] || { echo "× Release 资产不存在: $NAME @ $TAG"; exit 1; }
curl -sfL -H "$AUTH" -o "$DEST" "$URL"
echo "fetched: $NAME -> $DEST ($(stat -c%s "$DEST") bytes)"
