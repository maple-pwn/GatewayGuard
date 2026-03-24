"""Minimal touch UI for in-app verification."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse


router = APIRouter(tags=["ui"])


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>GatewayGuard Verify UI</title>
  <style>
    :root { --bg:#f3f6f8; --card:#ffffff; --text:#1a1f24; --btn:#0b5fff; --btn2:#156c37; --border:#d8e0e8; }
    body { margin:0; font-family: "Noto Sans", sans-serif; background: var(--bg); color: var(--text); }
    .wrap { padding: 14px; max-width: 880px; margin: 0 auto; }
    .card { background: var(--card); border:1px solid var(--border); border-radius: 12px; padding: 14px; margin-bottom: 12px; }
    h1 { margin: 0 0 8px 0; font-size: 22px; }
    .row { display:flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
    button { border:0; border-radius:10px; background: var(--btn); color:#fff; font-size:16px; min-height:48px; padding:10px 14px; }
    button.alt { background: var(--btn2); }
    input, select { font-size:16px; min-height:44px; border:1px solid var(--border); border-radius:10px; padding:0 10px; }
    pre { margin:0; white-space: pre-wrap; word-break: break-word; font-size:12px; max-height: 55vh; overflow:auto; background:#0f1720; color:#d8f1ff; border-radius:10px; padding:12px; }
    .hint { font-size: 13px; opacity: 0.8; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>GatewayGuard Android 验证面板</h1>
      <div class="hint">后端地址: <code>http://127.0.0.1:8000</code></div>
    </div>

    <div class="card">
      <div class="row">
        <button onclick="health()">后端健康检查</button>
        <button onclick="sysStatus()">初始化数据库/查看系统状态</button>
      </div>
      <div class="row">
        <select id="scenario">
          <option value="normal">normal</option>
          <option value="dos">dos</option>
          <option value="fuzzy">fuzzy</option>
          <option value="spoofing">spoofing</option>
          <option value="mixed">mixed</option>
        </select>
        <input id="count" type="number" value="120" min="1" max="1000" />
        <button class="alt" onclick="simulate()">生成模拟流量</button>
      </div>
      <div class="row">
        <button onclick="stats()">查看流量统计</button>
        <button onclick="detect()">触发异常检测</button>
        <button onclick="pickFile()">导入抓包文件</button>
      </div>
      <div class="row">
        <button onclick="logs()">查看最近日志</button>
      </div>
      <div class="hint">LLM API Key: 通过 Android 私有目录下的 <code>config.yaml</code> 配置。</div>
    </div>

    <div class="card">
      <div style="margin-bottom:8px;font-weight:600;">最近结果展示区</div>
      <pre id="result">{ "ready": true }</pre>
    </div>
  </div>
  <script>
    const out = document.getElementById("result");
    const show = (title, data) => out.textContent = title + "\\n" + JSON.stringify(data, null, 2);
    async function req(url, method = "GET") {
      const r = await fetch(url, { method });
      const t = await r.text();
      let parsed = t;
      try { parsed = JSON.parse(t); } catch (_) {}
      if (!r.ok) throw { status: r.status, body: parsed };
      return parsed;
    }
    async function health() {
      try { show("health", await req("/health/ready")); } catch (e) { show("health error", e); }
    }
    async function sysStatus() {
      try { show("system", await req("/api/system/status")); } catch (e) { show("system error", e); }
    }
    async function simulate() {
      const scenario = document.getElementById("scenario").value;
      const count = document.getElementById("count").value || "100";
      try { show("simulate", await req(`/api/traffic/simulate?scenario=${encodeURIComponent(scenario)}&count=${encodeURIComponent(count)}`, "POST")); }
      catch (e) { show("simulate error", e); }
    }
    async function stats() {
      try { show("stats", await req("/api/traffic/stats")); } catch (e) { show("stats error", e); }
    }
    async function detect() {
      try {
        const train = await req("/api/anomaly/train?limit=2000", "POST");
        const detectResult = await req("/api/anomaly/detect?limit=500", "POST");
        show("anomaly", { train, detect: detectResult });
      } catch (e) {
        show("anomaly error", e);
      }
    }
    function pickFile() {
      if (window.AndroidBridge && window.AndroidBridge.pickCaptureFile) {
        window.AndroidBridge.pickCaptureFile();
      } else {
        show("import", { error: "AndroidBridge unavailable. Use app shell." });
      }
    }
    async function logs() {
      try { show("logs", await req("/api/system/logs/recent?lines=120")); } catch (e) { show("logs error", e); }
    }
    window.onNativeImportResult = function (payload) {
      try { show("import", JSON.parse(payload)); } catch (_) { show("import", payload); }
    }
  </script>
</body>
</html>
"""


@router.get("/ui/", response_class=HTMLResponse)
async def ui_index():
    return HTMLResponse(content=HTML_PAGE)

