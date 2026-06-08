/* ===========================================================
   app.js — SentinelOps SIEM SPA (talks to FastAPI backend)
   =========================================================== */
(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const el = (h) => { const t = document.createElement("template"); t.innerHTML = h.trim(); return t.content.firstChild; };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const fmtTime = (t) => new Date(t).toLocaleTimeString("en-GB", { hour12: false });
  const fmtDT = (t) => new Date(t).toLocaleString("en-GB", { hour12: false });
  const sevTag = (s) => `<span class="tag ${s}">${s}</span>`;
  const ago = (t) => { if (!t) return "—"; const s = (Date.now() - t) / 1000; return s < 60 ? Math.floor(s) + "s ago" : s < 3600 ? Math.floor(s / 60) + "m ago" : Math.floor(s / 3600) + "h ago"; };
  const HOSTILE = new Set(["RU", "CN", "KP", "NG"]);

  const ST = { view: "dashboard", range: "24h", chat: [], charts: {}, streamTimer: null, lastSearch: "*", user: null };

  const NAV = [
    { sec: "Monitor" },
    { id: "dashboard", label: "Overview", ico: "▦" },
    { id: "search", label: "Search & Investigate", ico: "🔍" },
    { id: "stream", label: "Live Event Stream", ico: "📡" },
    { sec: "Detect & Respond" },
    { id: "ai", label: "AI Security Analyst", ico: "🤖" },
    { id: "alerts", label: "Findings / Incidents", ico: "🚨" },
    { id: "rules", label: "Detection Rules", ico: "⚙️" },
    { sec: "Manage" },
    { id: "sources", label: "Data Sources", ico: "🗄️" },
    { id: "mcp", label: "AI / MCP Connectors", ico: "🔌" },
    { id: "admin", label: "Users & Audit", ico: "🛡️", admin: true }
  ];

  function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 2200); }
  function destroyCharts() { Object.values(ST.charts).forEach((c) => { try { c.destroy(); } catch (e) {} }); ST.charts = {}; }

  async function boot() {
    try { ST.user = await API.me(); } catch (e) {
      if (String(e.message).includes("authenticated")) return; // api.js already redirected
      $("#app").innerHTML = `<div class="empty"><div class="big">🔌</div>Cannot reach the API.<br><span class="muted">Start the backend, then reload.</span></div>`; return;
    }
    renderShell();
    go("dashboard");
  }

  function renderShell() {
    const app = $("#app"); app.innerHTML = "";
    app.appendChild(el(`<div class="app-shell">
      <aside class="sidebar">
        <div class="brand"><div class="brand-logo">◈</div>
          <div><div class="brand-name">SentinelOps</div><div class="brand-sub">SIEM Platform</div></div></div>
        <nav class="nav" id="nav"></nav>
        <div class="sidebar-foot"><span class="live-dot"></span><span id="foot">Live ingest</span></div>
      </aside>
      <div class="main">
        <div class="topbar"><h1 id="title">Overview</h1>
          <span class="pill gold" id="riskpill">Risk —</span>
          <select class="time-select" id="range">
            <option value="15m">Last 15 min</option><option value="1h">Last 1 hour</option>
            <option value="4h">Last 4 hours</option><option value="24h" selected>Last 24 hours</option></select>
          <button class="btn sm ghost" id="reanalyze">↻ Re-analyze</button>
          <span class="pill" id="acct" title="${esc(ST.user.role)}">👤 ${esc(ST.user.username)} · ${esc(ST.user.role)}</span>
          <button class="btn sm ghost" id="logout">Logout</button></div>
        <div class="content" id="content"></div>
        <div class="statusbar"><span>● <b>Healthy</b> · 8 sources</span>
          <span id="sb-events">Events: —</span><span id="sb-findings">Findings: —</span>
          <span style="flex:1"></span><span class="muted">SentinelOps v2.4 · FastAPI + SQL · MCP-ready</span></div>
      </div></div>`));
    const nav = $("#nav");
    NAV.forEach((n) => {
      if (n.admin && ST.user.role !== "admin") return;
      if (n.sec) return nav.appendChild(el(`<div class="nav-section">${n.sec}</div>`));
      const b = el(`<button class="nav-item" data-id="${n.id}"><span class="ico">${n.ico}</span>${n.label}</button>`);
      b.onclick = () => go(n.id); nav.appendChild(b);
    });
    $("#range").onchange = (e) => { ST.range = e.target.value; rerender(); };
    $("#reanalyze").onclick = async () => { try { await API.analyze(); toast("Detection engine re-run"); await refreshBadges(); rerender(); } catch (e) { toast("Error: " + e.message); } };
    $("#logout").onclick = () => { window.location.href = "/logout"; };
  }

  async function refreshBadges() {
    try {
      const ov = await API.overview(ST.range);
      const p = $("#riskpill"); p.textContent = "Risk " + ov.risk_score + "/100";
      p.className = "pill " + (ov.risk_score >= 70 ? "red" : ov.risk_score >= 40 ? "gold" : "");
      $("#sb-events").textContent = "Events: " + ov.total_events.toLocaleString();
      $("#sb-findings").textContent = "Findings: " + ov.findings;
      $("#foot").textContent = ov.total_events.toLocaleString() + " events";
    } catch (e) {}
  }

  function go(id) {
    ST.view = id;
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.id === id));
    if (ST.streamTimer) { clearInterval(ST.streamTimer); ST.streamTimer = null; }
    rerender();
  }

  const TITLES = { dashboard: "Security Overview", search: "Search & Investigate", stream: "Live Event Stream", ai: "AI Security Analyst", alerts: "Findings / Incidents", rules: "Detection Rules", sources: "Data Sources", mcp: "AI / MCP Connectors", admin: "Users & Audit" };
  const VIEWS = { dashboard: viewDashboard, search: viewSearch, stream: viewStream, ai: viewAI, alerts: viewAlerts, rules: viewRules, sources: viewSources, mcp: viewMCP, admin: viewAdmin };

  async function rerender() {
    $("#title").textContent = TITLES[ST.view] || "Overview";
    destroyCharts();
    const c = $("#content"); c.innerHTML = `<div class="loader"></div>`;
    refreshBadges();
    try { await (VIEWS[ST.view] || viewDashboard)(c); }
    catch (e) { c.innerHTML = `<div class="card"><b style="color:var(--red)">Error:</b> ${esc(e.message)}</div>`; }
  }

  function kpi(label, value, delta, dir, gold) {
    return `<div class="card kpi ${gold ? "gold" : ""}"><div class="label">${label}</div><div class="value">${value}</div>
      <div class="delta ${dir}">${dir === "up" ? "▲" : "▼"} ${esc(delta)}</div><div class="kpi-accent"></div></div>`;
  }
  function bars(node, pairs, hostile) {
    if (!pairs.length) { node.innerHTML = '<div class="muted">No data</div>'; return; }
    const max = pairs[0][1];
    node.innerHTML = pairs.map(([k, v]) => {
      const d = hostile && HOSTILE.has(k);
      return `<div class="barrow"><span>${d ? "⚠️ " : ""}<span class="mono">${esc(k)}</span></span><span class="n">${v}</span></div>
        <div class="bar"><i style="width:${Math.max(4, v / max * 100)}%${d ? ";background:#b3261e" : ""}"></i></div>`;
    }).join("");
  }

  // ============ DASHBOARD ============
  async function viewDashboard(c) {
    const ov = await API.overview(ST.range);
    c.innerHTML = "";
    c.appendChild(el(`<div class="grid cols-4 mb">
      ${kpi("Risk Score", ov.risk_score + "/100", ov.risk_score >= 70 ? "Critical exposure" : ov.risk_score >= 40 ? "Elevated" : "Under control", ov.risk_score >= 40 ? "up" : "down", true)}
      ${kpi("Events (range)", ov.total_events.toLocaleString(), "across 8 sources", "down")}
      ${kpi("Open Findings", ov.findings, ov.critical + " critical · " + ov.high + " high", ov.critical ? "up" : "down")}
      ${kpi("Blocked / Failed", ov.blocked.toLocaleString(), "deny + auth failures", "up")}</div>`));
    c.appendChild(el(`<div class="grid cols-3 mb">
      <div class="card" style="grid-column:span 2"><h3>📈 Event Volume by Severity <span class="sub">· ${ST.range}</span></h3><canvas id="ch-vol" height="120"></canvas></div>
      <div class="card"><h3>🎯 Events by Source Type</h3><canvas id="ch-src" height="210"></canvas></div></div>`));
    c.appendChild(el(`<div class="grid cols-3 mb">
      <div class="card"><h3>🌍 Top Source Countries</h3><div id="geo"></div></div>
      <div class="card"><h3>🔥 Top Talkers (src IP)</h3><div id="talk"></div></div>
      <div class="card"><h3>🩺 Source Health</h3><div id="health"></div></div></div>`));
    c.appendChild(el(`<div class="card"><h3>🚨 Latest Findings <span class="sub">· AI-correlated</span></h3><div id="latest"></div></div>`));

    // volume chart
    const sevs = ["critical", "high", "medium", "low", "info"];
    const colors = { critical: "#b3261e", high: "#b5660a", medium: "#cba258", low: "#00754A", info: "#9fb8ad" };
    ST.charts.vol = new Chart($("#ch-vol"), {
      type: "bar", data: { labels: ov.timeline.map((b) => fmtTime(b.t).slice(0, 5)),
        datasets: sevs.map((s) => ({ label: s, data: ov.timeline.map((b) => b[s] || 0), backgroundColor: colors[s], stack: "s", borderRadius: 2 })) },
      options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 10 } } } },
        scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, grid: { color: "#f0efec" } } } }
    });
    const srcPairs = Object.entries(ov.by_source);
    const pal = ["#1E3932", "#006241", "#00754A", "#2b5148", "#cba258", "#dfc49d", "#d4e9e2", "#9fb8ad"];
    ST.charts.src = new Chart($("#ch-src"), {
      type: "doughnut", data: { labels: srcPairs.map((p) => p[0]), datasets: [{ data: srcPairs.map((p) => p[1]), backgroundColor: pal, borderWidth: 2, borderColor: "#fff" }] },
      options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 10 } } } }, cutout: "62%" }
    });
    bars($("#geo"), ov.by_country, true);
    bars($("#talk"), ov.top_talkers, false);
    $("#health").innerHTML = ov.sources_health.map((s) => {
      const cls = s.count === 0 ? "r" : s.count < 10 ? "a" : "g";
      const st = s.count === 0 ? "no data" : s.count < 10 ? "low volume" : "streaming";
      return `<div class="health"><span class="dot ${cls}"></span><b style="flex:1">${s.sourcetype}</b><span class="muted">${s.count} ev · ${st}</span></div>`;
    }).join("");
    const f = (await API.findings()).findings;
    renderFindings($("#latest"), f.slice(0, 6), true);
  }

  // ============ SEARCH ============
  async function viewSearch(c) {
    c.innerHTML = "";
    c.appendChild(el(`<div class="search-bar"><div class="search-input-wrap">
      <input class="search-input" id="spl" placeholder='Search… e.g.  action=failure sourcetype=linux_secure | stats count by src_ip'></div>
      <button class="btn" id="run">▶ Search</button></div>`));
    const samples = ["*", "action=failure | stats count by src_ip", "sourcetype=firewall action=deny | top dest_port",
      "sqlmap | table _time src_ip uri status", "country=KP OR country=RU", "bytes>1000000 | stats sum(bytes) by src_ip",
      "severity=critical", "sourcetype=apache_access status>=500 | timechart span=1h"];
    const chips = el(`<div class="chips"></div>`);
    samples.forEach((s) => { const ch = el(`<button class="chip code">${esc(s)}</button>`); ch.onclick = () => { $("#spl").value = s; runSearch(); }; chips.appendChild(ch); });
    c.appendChild(chips);
    c.appendChild(el(`<div id="results"></div>`));
    $("#spl").value = ST.lastSearch;
    $("#run").onclick = runSearch;
    $("#spl").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });
    runSearch();
  }

  async function runSearch() {
    const q = ($("#spl").value || "*").trim() || "*"; ST.lastSearch = q;
    const node = $("#results"); node.innerHTML = `<div class="loader"></div>`;
    let res;
    try { res = await API.search(q, ST.range); }
    catch (e) { node.innerHTML = `<div class="card"><b style="color:var(--red)">Query error:</b> ${esc(e.message)}</div>`; return; }
    node.innerHTML = "";
    node.appendChild(el(`<div class="muted mb"><b style="color:var(--green-accent)">${res.count.toLocaleString()}</b> results · <span class="mono">${esc(q.length > 70 ? q.slice(0, 70) + "…" : q)}</span></div>`));
    if (res.type === "timechart") {
      node.appendChild(el(`<div class="card"><h3>📈 Timechart</h3><canvas id="tc" height="90"></canvas></div>`));
      ST.charts.tc = new Chart($("#tc"), { type: "line", data: { labels: res.rows.map((r) => fmtTime(r._time).slice(0, 5)), datasets: [{ data: res.rows.map((r) => r.count), borderColor: "#00754A", backgroundColor: "rgba(0,117,74,.15)", fill: true, tension: .3, pointRadius: 2 }] }, options: { plugins: { legend: { display: false } }, scales: { y: { grid: { color: "#f0efec" } }, x: { grid: { display: false } } } } });
      return;
    }
    if (res.type === "table") {
      node.appendChild(tableFor(res.columns, res.rows));
      if (res.columns.length === 2 && res.rows.length > 1 && res.rows.length <= 15) {
        node.appendChild(el(`<div class="card mt"><h3>📊 Visualization</h3><canvas id="tb" height="90"></canvas></div>`));
        const vc = res.columns[1];
        ST.charts.tb = new Chart($("#tb"), { type: "bar", data: { labels: res.rows.map((r) => String(r[res.columns[0]]).slice(0, 18)), datasets: [{ data: res.rows.map((r) => r[vc]), backgroundColor: "#00754A", borderRadius: 3 }] }, options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { grid: { color: "#f0efec" } }, y: { grid: { display: false } } } } });
      }
      return;
    }
    const list = el(`<div class="card" style="padding:0"><div class="scrolly" style="max-height:580px"></div></div>`);
    const inner = $(".scrolly", list);
    if (!res.rows.length) inner.innerHTML = `<div class="empty"><div class="big">🔍</div>No events match this query.</div>`;
    res.rows.forEach((e) => {
      const fields = Object.keys(e).filter((k) => !["_id", "_raw", "_time", "severity"].includes(k)).slice(0, 7).map((k) => `<span class="fk"><b>${k}</b>=${esc(e[k])}</span>`).join("");
      inner.appendChild(el(`<div class="event-row"><div class="flex between center"><span class="event-time">${fmtDT(e._time)}</span> ${sevTag(e.severity)}</div>
        <div class="event-raw">${esc(e._raw)}</div><div class="event-fields"><span class="fk"><b>sourcetype</b>=${e.sourcetype}</span><span class="fk"><b>host</b>=${e.host}</span>${fields}</div></div>`));
    });
    node.appendChild(list);
  }
  function tableFor(cols, rows) {
    const head = cols.map((c) => `<th>${esc(c)}</th>`).join("");
    const body = rows.map((r) => "<tr>" + cols.map((c) => { let v = r[c]; if (c === "_time") v = fmtDT(v); return `<td class="mono ${typeof r[c] === "number" || c === "count" ? "right" : ""}">${esc(v)}</td>`; }).join("") + "</tr>").join("");
    return el(`<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`);
  }

  // ============ STREAM ============
  async function viewStream(c) {
    c.innerHTML = "";
    c.appendChild(el(`<div class="card mb"><div class="flex between center"><h3 style="margin:0">📡 Live Event Stream <span class="sub">· tailing indexer</span></h3><span class="pill"><span class="live-dot"></span>STREAMING</span></div></div>`));
    const list = el(`<div class="card" style="padding:0"><div class="scrolly" id="stream" style="max-height:620px"></div></div>`);
    c.appendChild(list);
    const stream = $("#stream", list);
    const seed = (await API.recent(25)).events;
    seed.forEach((e) => stream.appendChild(streamRow(e)));
    let pool = seed.slice();
    ST.streamTimer = setInterval(async () => {
      try { pool = (await API.recent(8)).events; } catch (e) { return; }
      const e = pool[Math.floor(Math.random() * pool.length)];
      if (!e) return;
      const clone = Object.assign({}, e, { _time: Date.now() });
      const row = streamRow(clone); row.style.background = "#d4e9e2";
      stream.insertBefore(row, stream.firstChild);
      setTimeout(() => (row.style.background = ""), 800);
      while (stream.children.length > 60) stream.removeChild(stream.lastChild);
    }, 1600);
  }
  function streamRow(e) {
    return el(`<div class="event-row"><div class="flex between center"><span class="event-time">${fmtDT(e._time)}</span> ${sevTag(e.severity)}</div>
      <div class="event-raw">${esc(e._raw)}</div><div class="event-fields"><span class="fk"><b>sourcetype</b>=${e.sourcetype}</span><span class="fk"><b>host</b>=${e.host}</span>${e.src_ip ? `<span class="fk"><b>src_ip</b>=${e.src_ip}</span>` : ""}</div></div>`);
  }

  // ============ AI ============
  async function viewAI(c) {
    c.innerHTML = "";
    c.appendChild(el(`<div class="ai-wrap">
      <div class="card chat"><h3>🤖 AI Security Analyst <span class="sub">· ask anything about your environment</span></h3>
        <div class="chat-log" id="chatlog"></div>
        <div class="chat-input"><input id="chatq" placeholder="e.g. What should I do about the brute force attack?"><button class="btn" id="send">Send</button></div></div>
      <div><div class="card mb"><h3>⚡ Quick prompts</h3><div id="prompts"></div></div>
        <div class="card"><h3>🧠 Detection summary</h3><div id="aimini"></div></div></div></div>`));
    const log = $("#chatlog");
    if (!ST.chat.length) { const a = await API.chat("summary", ST.range); ST.chat.push({ role: "ai", html: a.answer }); }
    ST.chat.forEach((m) => log.appendChild(msgEl(m)));
    log.scrollTop = log.scrollHeight;
    const prompts = ["Give me a full security summary", "What should I do about the malware?", "Show me the brute force attack", "Top source IPs", "Any data exfiltration?", "Events from CN"];
    const pc = $("#prompts");
    prompts.forEach((p) => { const b = el(`<button class="chip" style="display:block;width:100%;text-align:left;margin-bottom:6px">${esc(p)}</button>`); b.onclick = () => sendChat(p); pc.appendChild(b); });
    const f = (await API.findings()).findings;
    const sc = (s) => f.filter((x) => x.severity === s).length;
    $("#aimini").innerHTML = `<div class="barrow"><span>Critical</span><span class="n" style="color:#b3261e">${sc("critical")}</span></div>
      <div class="barrow"><span>High</span><span class="n" style="color:#b5660a">${sc("high")}</span></div>
      <div class="barrow"><span>Medium</span><span class="n" style="color:#8a6a22">${sc("medium")}</span></div>`;
    $("#send").onclick = () => { const v = $("#chatq").value.trim(); if (v) sendChat(v); };
    $("#chatq").addEventListener("keydown", (e) => { if (e.key === "Enter") { const v = e.target.value.trim(); if (v) sendChat(v); } });
  }
  function msgEl(m) { return el(`<div class="msg ${m.role}">${m.role === "user" ? esc(m.html) : m.html}</div>`); }
  async function sendChat(text) {
    const log = $("#chatlog"); const input = $("#chatq"); if (input) input.value = "";
    ST.chat.push({ role: "user", html: text }); log.appendChild(msgEl({ role: "user", html: text }));
    const typing = el(`<div class="msg ai"><span class="typing"><span></span><span></span><span></span></span></div>`);
    log.appendChild(typing); log.scrollTop = log.scrollHeight;
    let ans = "Sorry, I hit an error."; try { ans = (await API.chat(text, ST.range)).answer; } catch (e) {}
    typing.remove(); ST.chat.push({ role: "ai", html: ans });
    log.appendChild(msgEl({ role: "ai", html: ans })); log.scrollTop = log.scrollHeight;
  }

  // ============ ALERTS ============
  async function viewAlerts(c) {
    c.innerHTML = "";
    const data = await API.findings(); const f = data.findings;
    const counts = ["critical", "high", "medium", "low"].map((s) => f.filter((x) => x.severity === s).length);
    c.appendChild(el(`<div class="grid cols-4 mb">
      ${kpi("Critical", counts[0], "immediate action", counts[0] ? "up" : "down")}
      ${kpi("High", counts[1], "investigate now", counts[1] ? "up" : "down")}
      ${kpi("Medium", counts[2], "monitor", "down", true)}
      ${kpi("Total Findings", f.length, "AI-correlated", "up")}</div>`));
    c.appendChild(el(`<div class="card"><h3>🚨 Incidents <span class="sub">· correlated by detection engine, sorted by severity × confidence</span></h3><div id="flist"></div></div>`));
    renderFindings($("#flist"), f, false);
  }
  function renderFindings(node, findings, compact) {
    if (!findings.length) { node.innerHTML = `<div class="empty"><div class="big">✅</div>No active threats detected in this window.</div>`; return; }
    node.innerHTML = "";
    findings.forEach((f) => {
      node.appendChild(el(`<div class="finding ${f.severity}">
        <div class="finding-h">${sevTag(f.severity)} ${esc(f.title)} <span style="flex:1"></span><span class="muted" style="font-size:11px">${f.confidence}% confidence</span></div>
        <div class="finding-meta"><span>🎯 <b>${esc(f.tactic)}</b></span><span class="mitre">${esc(f.mitre)}</span>${f.src_ip ? `<span>📍 <span class="mono">${esc(f.src_ip)}</span></span>` : ""}${f.country ? `<span>🌍 ${esc(f.country)}</span>` : ""}${f.host ? `<span>🖥️ ${esc(f.host)}</span>` : ""}<span>🕐 ${f.count} event(s)</span></div>
        <div class="finding-desc"><b>Evidence:</b> ${esc(f.evidence)}</div>
        ${compact ? "" : `<div class="finding-desc"><b>➡️ Recommended action:</b> ${esc(f.recommendation)}</div>
        <div class="mt"><button class="btn sm" data-inc="${f.id}">Create incident</button> <button class="btn sm ghost" data-ai="${esc(f.title)}">Ask AI analyst</button> <button class="btn sm ghost" data-inv="${esc(f.src_ip || f.host || "")}">Investigate</button></div>`}
      </div>`));
    });
    if (!compact) {
      node.querySelectorAll("[data-inc]").forEach((b) => b.onclick = async () => { try { await API.createIncident(b.dataset.inc); toast("Incident " + b.dataset.inc + " created ✓"); } catch (e) { toast("Error: " + e.message); } });
      node.querySelectorAll("[data-ai]").forEach((b) => b.onclick = () => { go("ai"); setTimeout(() => sendChat("Tell me about: " + b.dataset.ai), 200); });
      node.querySelectorAll("[data-inv]").forEach((b) => b.onclick = () => { if (!b.dataset.inv) return; go("search"); setTimeout(() => { $("#spl").value = (/\d+\.\d+/.test(b.dataset.inv) ? "src_ip=" : "host=") + b.dataset.inv; runSearch(); }, 250); });
    }
  }

  // ============ RULES ============
  async function viewRules(c) {
    c.innerHTML = "";
    const data = await API.rules(); const rules = data.rules;
    const on = rules.filter((r) => r.enabled).length;
    c.appendChild(el(`<div class="card mb"><div class="flex between center"><h3 style="margin:0">⚙️ Detection Rules <span class="sub">· ${on}/${rules.length} enabled</span></h3><span class="pill">${on} active</span></div></div>`));
    const box = el(`<div></div>`); c.appendChild(box);
    rules.forEach((r) => {
      const row = el(`<div class="rule"><div class="rico">${r.icon || "⚙️"}</div>
        <div style="flex:1"><div style="font-weight:700">${esc(r.name)} ${sevTag(r.severity)}</div><div class="muted" style="font-size:12px;margin-top:2px">${esc(r.description)}</div></div>
        <button class="toggle ${r.enabled ? "on" : ""}"></button></div>`);
      $(".toggle", row).onclick = async (e) => {
        const res = await API.toggleRule(r.id);
        e.target.classList.toggle("on", res.enabled);
        toast(`Rule "${r.name}" ${res.enabled ? "enabled" : "disabled"} · findings recomputed`);
        refreshBadges();
      };
      box.appendChild(row);
    });
  }

  // ============ SOURCES ============
  async function viewSources(c) {
    c.innerHTML = "";
    const data = await API.sources(ST.range);
    const tb = data.sources.map((s) => `<tr><td><b>${s.sourcetype}</b></td><td>${s.category}</td><td class="mono right">${s.count.toLocaleString()}</td>
      <td>${ago(s.last_event)}</td><td>${s.status === "healthy" ? '<span class="tag low">● healthy</span>' : '<span class="tag critical">● offline</span>'}</td></tr>`).join("");
    c.appendChild(el(`<div class="card mb"><h3>🗄️ Connected Data Sources <span class="sub">· forwarders reporting to indexer:01</span></h3>
      <div class="table-wrap"><table><thead><tr><th>Source Type</th><th>Category</th><th>Events (range)</th><th>Last Event</th><th>Status</th></tr></thead><tbody>${tb}</tbody></table></div></div>`));
    c.appendChild(el(`<div class="card"><h3>➕ Add Data Source</h3><div class="muted mb">Ingest via the REST API (<code>POST /api/ingest</code>), syslog, HTTP Event Collector, or cloud API.</div>
      <pre class="code">curl -X POST http://localhost:8000/api/ingest \\
  -H "Content-Type: application/json" \\
  -d '{"sourcetype":"firewall","host":"fw-edge-02","severity":"low",
       "raw":"action=deny src=1.2.3.4","fields":{"action":"deny","src_ip":"1.2.3.4"}}'</pre></div>`));
  }

  // ============ MCP ============
  async function viewMCP(c) {
    c.innerHTML = "";
    let tools = [];
    try { tools = (await API.mcpTools()).tools; } catch (e) {}
    c.appendChild(el(`<div class="card mb"><h3>🔌 AI &amp; MCP Connectors <span class="sub">· Model Context Protocol</span></h3>
      <div class="muted">SentinelOps exposes its search, findings, and response actions as <b>live MCP tools</b> at <code>/mcp/tools</code> and <code>/mcp/call</code>, plus a stdio MCP server for Claude Desktop. Any compatible AI agent can query telemetry and drive investigations — the built-in analyst uses the same backend.</div></div>`));
    const grid = el(`<div class="grid cols-2 mb"></div>`);
    const icons = { "siem.search": "🔍", "siem.get_findings": "🚨", "siem.analyze": "🧠", "siem.overview": "📈", "siem.create_incident": "📋" };
    tools.forEach((t) => grid.appendChild(el(`<div class="card"><div class="flex center gap">
      <div class="rico" style="width:42px;height:42px;border-radius:50%;display:grid;place-items:center;font-size:18px;background:var(--green-light)">${icons[t.name] || "🔧"}</div>
      <div style="flex:1"><div class="mono" style="font-weight:700;color:var(--green)">${esc(t.name)}</div><div class="muted" style="font-size:12px">${esc(t.description)}</div></div>
      <span class="tag low">online</span></div></div>`)));
    c.appendChild(grid);
    c.appendChild(el(`<div class="card"><h3>📜 Connect an agent (Claude Desktop)</h3>
      <pre class="code">// claude_desktop_config.json
{
  "mcpServers": {
    "sentinelops": {
      "command": "python",
      "args": ["-m", "app.mcp_server"],
      "env": { "SIEM_API_URL": "http://localhost:8000" }
    }
  }
}

// Or call the HTTP MCP endpoint directly:
curl -X POST http://localhost:8000/mcp/call \\
  -d '{"tool":"siem.get_findings","arguments":{"severity":"critical"}}'</pre></div>`));
  }

  // ============ ADMIN (users & audit) ============
  async function viewAdmin(c) {
    c.innerHTML = "";
    if (ST.user.role !== "admin") { c.innerHTML = `<div class="empty"><div class="big">🔒</div>Admin access required.</div>`; return; }
    let users = [], audit = [];
    try { users = (await API.users()).users; audit = (await API.audit()).audit; }
    catch (e) { c.innerHTML = `<div class="card"><b style="color:var(--red)">Error:</b> ${esc(e.message)}</div>`; return; }
    const roleTag = (r) => `<span class="tag ${r === "admin" ? "critical" : r === "analyst" ? "medium" : "low"}">${esc(r)}</span>`;
    const utb = users.map((u) => `<tr><td><b>${esc(u.username)}</b></td><td>${esc(u.email)}</td><td>${roleTag(u.role)}</td>
      <td>${u.active ? '<span class="tag low">active</span>' : '<span class="tag info">disabled</span>'}</td>
      <td class="mono">${u.last_login ? new Date(u.last_login + "Z").toLocaleString("en-GB", { hour12: false }) : "—"}</td></tr>`).join("");
    c.appendChild(el(`<div class="card mb"><h3>👥 Users <span class="sub">· ${users.length} accounts · RBAC: admin › analyst › viewer</span></h3>
      <div class="table-wrap"><table><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th></tr></thead><tbody>${utb}</tbody></table></div></div>`));
    const atb = audit.map((a) => `<tr><td class="mono">${a.ts ? new Date(a.ts + "Z").toLocaleString("en-GB", { hour12: false }) : "—"}</td>
      <td><b>${esc(a.actor || "—")}</b></td><td><span class="tag ${a.action && a.action.includes("fail") ? "critical" : "low"}">${esc(a.action)}</span></td>
      <td>${esc(a.detail || "")}</td><td class="mono">${esc(a.ip || "")}</td></tr>`).join("");
    c.appendChild(el(`<div class="card"><h3>📜 Security Audit Log <span class="sub">· most recent events</span></h3>
      <div class="table-wrap scrolly" style="max-height:420px"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody>${atb || '<tr><td colspan=5 class="muted">No entries</td></tr>'}</tbody></table></div></div>`));
  }

  boot();
})();
