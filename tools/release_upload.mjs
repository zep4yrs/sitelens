// CNB Release 资产上传（release_upload.sh 的 Node 复刻，免 jq）。
// 用法：CNB_TOKEN=... SITLENS_TAG=v4.0.0 [SITLENS_BODY_FILE=xx.md] node release_upload.mjs <file>...
// API 语义与原脚本一致：Accept: application/json 必须；PUT 后 POST verify_url 资产才可见。
import fs from "fs";

const TOKEN = process.env.CNB_TOKEN;
const TAG = process.env.SITLENS_TAG || "v" + JSON.parse(fs.readFileSync(new URL("../desktop/package.json", import.meta.url), "utf8")).version;
const BODY_FILE = process.env.SITLENS_BODY_FILE;
const REPO = process.env.SITLENS_REPO || "feng-qiao/sitelens";
const API = `https://api.cnb.cool/${REPO}`;
const H = { "Authorization": `Bearer ${TOKEN}`, "Accept": "application/json" };

async function j(method, path, body, extra = {}) {
  const r = await fetch(API + path, {
    method,
    headers: { ...H, ...(body ? { "Content-Type": "application/json" } : {}), ...extra },
    body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined
  });
  const t = await r.text();
  if (!r.ok) throw new Error(`${method} ${path} -> ${r.status}: ${t.slice(0, 300)}`);
  return t ? JSON.parse(t) : {};
}

let rid;
const rel = await j("GET", `/-/releases/tags/${TAG}`).catch(() => null);
if (rel && rel.id) {
  rid = rel.id;
  console.log("release exists:", TAG, "id=", rid);
} else {
  const body = BODY_FILE && fs.existsSync(BODY_FILE) ? fs.readFileSync(BODY_FILE, "utf8") : undefined;
  const created = await j("POST", "/-/releases", {
    tag_name: TAG, name: `SiteLens ${TAG}`, ...(body ? { body } : {})
  });
  rid = created.id;
  console.log("release created:", TAG, "id=", rid, body ? "(含发行说明)" : "");
}

for (const f of process.argv.slice(2)) {
  const name = f.split(/[\\/]/).pop();
  const buf = fs.readFileSync(f);
  const up = await j("POST", `/-/releases/${rid}/asset-upload-url`, {
    asset_name: name, size: buf.length
  });
  const put = await fetch(up.upload_url, { method: "PUT", body: buf });
  if (!put.ok) throw new Error(`PUT ${name} -> ${put.status}`);
  if (up.verify_url) {
    const v = await fetch(up.verify_url, { method: "POST", headers: H });
    if (!v.ok) throw new Error(`verify ${name} -> ${v.status}`);
  }
  console.log("uploaded:", name, buf.length, "bytes");
}
console.log("DONE", TAG);
