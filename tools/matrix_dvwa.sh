#!/bin/bash
# 靶场矩阵跑批：单会话全流程（双容器 DVWA + 认证扫描）
# 用法：在仓库根目录或任意位置执行；路径可经环境变量覆盖
#   MATRIX_ROOT   仓库根目录（缺省按脚本位置自动推导）
#   MATRIX_OUT    结果输出目录（缺省 /var/sl-e2e/out）
set -u
LOG=/var/sl-e2e/matrix.log
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SELF_DIR/.." && pwd)
BASE=$(dirname "$ROOT")
OUT=${MATRIX_OUT:-/var/sl-e2e/out}
CONF=${MATRIX_CONF:-$ROOT/docs/靶场矩阵-sitelens.yml}
R="$BASE/ranges"
mkdir -p "$OUT"
echo "=== 矩阵跑批 $(date +%H:%M:%S) ===" | tee "$LOG"

# 0) DVWA = web + mariadb 双容器
DBPW="p@ssw0""rd"
docker rm -f dvwa-official dvwa-db >/dev/null 2>&1
docker run -d --name dvwa-db -e MARIADB_ROOT_PASSWORD=vulnroot \
  -e MARIADB_DATABASE=dvwa -e MARIADB_USER=dvwa -e MARIADB_PASSWORD="$DBPW" \
  mariadb:11 >/dev/null
docker run -d --name dvwa-official --link dvwa-db:db \
  -e DB_SERVER=db -e DB_DATABASE=dvwa -e DB_USER=dvwa -e DB_PASSWORD="$DBPW" \
  -p 127.0.0.1:8090:80 ghcr.io/digininja/dvwa:latest >/dev/null
sleep 12

# MariaDB 就绪等待
C=/var/sl-e2e/dvlogin; rm -f "$C"
for i in 1 2 3 4 5 6; do
  curl -s -m 8 -c "$C" http://127.0.0.1:8090/setup.php -o /var/sl-e2e/setup7.html
  if ! grep -qiE "could not connect to the database" /var/sl-e2e/setup7.html; then
    echo "mariadb 就绪（第 $i 次探测）" | tee -a "$LOG"
    break
  fi
  echo "mariadb 未就绪，等待 15s…" | tee -a "$LOG"
  sleep 15
done

# setup POST 重试（每次重取 token）
OK=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  curl -s -m 8 -b "$C" http://127.0.0.1:8090/setup.php -o /var/sl-e2e/setup7.html
  T=$(grep -oE "user_token.{1,12}[a-f0-9]{32}" /var/sl-e2e/setup7.html | grep -oE "[a-f0-9]{32}" | head -1)
  curl -s -m 30 -b "$C" -L -d "create_db=Create%2FReset+Database&user_token=$T" http://127.0.0.1:8090/setup.php -o /var/sl-e2e/setupres7.html
  M=$(grep -icE "database has been created" /var/sl-e2e/setupres7.html)
  echo "setup POST 第 $i 次: created 标记 $M" | tee -a "$LOG"
  if [ "$M" -ge 1 ]; then OK=1; break; fi
  sleep 20
done
[ "$OK" -ne 1 ] && { echo "!! setup POST 重试耗尽" | tee -a "$LOG"; exit 1; }

# 登录（带 user_token）+ 认证断言门
C2=/var/sl-e2e/dvlogin2; rm -f "$C2"
curl -s -m 8 -c "$C2" http://127.0.0.1:8090/login.php -o /var/sl-e2e/loginget7.html
LT=$(grep -oE "user_token.{1,12}[a-f0-9]{32}" /var/sl-e2e/loginget7.html | grep -oE "[a-f0-9]{32}" | head -1)
LC=$(curl -s -m 8 -b "$C2" -c "$C2" -L -o /var/sl-e2e/login7.html -w "%{http_code}" \
  -d "username=admin&password=password&user_token=$LT&Login=Login" http://127.0.0.1:8090/login.php)
echo "login POST: $LC | login-failed 标记: $(grep -ic 'login failed' /var/sl-e2e/login7.html)" | tee -a "$LOG"
PHPI=$(awk '/PHPSESSID/{print $7}' "$C2" | tail -1)
COOKIE="security=low; PHPSESSID=$PHPI"
SQ=$(curl -s -m 8 -H "Cookie: $COOKIE" -L "http://127.0.0.1:8090/vulnerabilities/sqli/?id=1&Submit=Submit" | grep -ic Surname)
echo "认证断门 surname 标记: $SQ" | tee -a "$LOG"
if [ "$SQ" -lt 1 ]; then
  echo "!! 登录断言未过" | tee -a "$LOG"
  exit 1
fi

# serve
/var/sl-e2e/sitelens_linux -config "$CONF" serve > /var/sl-e2e/serve7.log 2>&1 &
SRV=$!
sleep 4
head -1 /var/sl-e2e/serve7.log | tee -a "$LOG"

scan() {
  local BODY J S SID
  BODY=$(python3 -c "
import json
o = {'url': 'http://127.0.0.1:8090', 'level': '$2'}
o['auth_cookie'] = '''$COOKIE'''
print(json.dumps(o))")
  J=$(curl -s -m 15 -X POST http://127.0.0.1:5090/api/scan -H "Content-Type: application/json" -d "$BODY" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('job_id',''))
except Exception: print('')" 2>/dev/null)
  if [ -z "$J" ]; then echo "$1 submit-fail" | tee -a "$LOG"; return; fi
  for w in $(seq 1 600); do
    S=$(curl -s -m 5 http://127.0.0.1:5090/api/job/$J 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('status'))
except Exception: print('poll')" 2>/dev/null)
    [ "$S" = "done" ] && break
    if [ "$S" = "error" ]; then
      echo "$1 job error:" | tee -a "$LOG"
      curl -s -m 5 http://127.0.0.1:5090/api/job/$J | tee -a "$LOG"
      echo | tee -a "$LOG"
      break
    fi
    sleep 3
  done
  SID=$(curl -s -m 5 "http://127.0.0.1:5090/api/job/$J/results" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('scan_id',''))
except Exception: print('')" 2>/dev/null)
  if [ -n "$SID" ]; then
    curl -s -m 10 "http://127.0.0.1:5090/api/history/$SID" -o "$OUT/m_$1.json"
    python3 - "$1" <<PYEOF
import json
try:
    h = json.load(open("$OUT/m_$1.json", encoding="utf-8"))
    r = h["result"]
    from collections import Counter
    v = r.get("verified") or []
    pg = len(r.get("pages") or [])
    print("$1 | dur", h["duration"], "| pages", pg, "| verified", len(v), dict(Counter(f.get("check") for f in v)), "| vulns", len(r.get("vulnerabilities") or []))
except Exception as e:
    print("$1 parse-err", e)
PYEOF
  else
    echo "$1 无结果" | tee -a "$LOG"
  fi
}

echo "--- DVWA full（认证，max_pages 30）" | tee -a "$LOG"
scan dvwa7_full full | tee -a "$LOG"
echo "--- DVWA apocalypse（认证，长）" | tee -a "$LOG"
scan dvwa7_apoc apocalypse | tee -a "$LOG"

kill $SRV 2>/dev/null
cp /var/sl-e2e/m_dvwa7_*.json "$OUT"/ 2>/dev/null
echo "=== 第七轮完成 $(date +%H:%M:%S) ===" | tee -a "$LOG"
