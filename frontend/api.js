/* api.js — REST client. Adds CSRF header for state-changing calls and
   redirects to /login on 401 (session expired / unauthenticated). */
const API = (() => {
  function getCookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : "";
  }
  async function req(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    const method = (opts.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = getCookie("sops_csrf");
    const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts, { headers }));
    if (res.status === 401) { window.location.href = "/login"; throw new Error("Not authenticated"); }
    if (!res.ok) {
      let msg = res.statusText;
      try { msg = (await res.json()).detail || msg; } catch (e) {}
      throw new Error(msg);
    }
    return res.json();
  }
  return {
    health: () => req("/api/health"),
    me: () => req("/api/me"),
    overview: (range) => req(`/api/stats/overview?range=${range}`),
    search: (query, range) => req("/api/search", { method: "POST", body: JSON.stringify({ query, range }) }),
    findings: (sev) => req("/api/findings" + (sev ? `?severity=${sev}` : "")),
    analyze: () => req("/api/analyze", { method: "POST" }),
    rules: () => req("/api/rules"),
    toggleRule: (id) => req(`/api/rules/${id}`, { method: "PATCH" }),
    sources: (range) => req(`/api/sources?range=${range}`),
    recent: (limit) => req(`/api/stream/recent?limit=${limit}`),
    incidents: () => req("/api/incidents"),
    createIncident: (finding_id) => req("/api/incidents", { method: "POST", body: JSON.stringify({ finding_id }) }),
    chat: (message, range) => req("/api/ai/chat", { method: "POST", body: JSON.stringify({ message, range }) }),
    mcpTools: () => req("/mcp/tools"),
    users: () => req("/api/users"),
    audit: () => req("/api/audit?limit=80"),
  };
})();
