HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relaygate</title>
<style>
body{font:16px system-ui;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#152238}
input,button{font:inherit;padding:.5rem;margin:.3rem}table{border-collapse:collapse;width:100%}
th,td{padding:.6rem;text-align:left;border-bottom:1px solid #ccc}pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style></head><body>
<h1>Relaygate</h1><p>Agent status, spend and audit history.</p>
<form id="login"><label>Admin token <input id="token" type="password" autocomplete="off" required></label>
<button>Refresh</button></form><p id="status" role="status"></p>
<h2>Agents</h2><table><thead><tr><th>Name</th><th>Provider</th><th>Status</th><th>Daily spend / cap</th><th>Monthly spend / cap</th><th>Action</th></tr></thead><tbody id="agents"></tbody></table>
<h2>Audit</h2><button id="verify">Verify chain</button><pre id="audit"></pre>
<script src="/dashboard.js" defer></script></body></html>'''

JS = r'''"use strict";
const el = id => document.getElementById(id);
async function api(path, method="GET") {
  const response = await fetch(path, {method, cache:"no-store", headers:{
    "Authorization":"Bearer " + el("token").value, "Content-Type":"application/json"
  }, ...(method === "POST" ? {body:"{}"} : {})});
  const data = await response.json();
  if (!response.ok) throw new Error(data.reason || "Request failed");
  return data;
}
async function refresh() {
  try {
    const {agents} = await api("/v1/agents");
    el("agents").replaceChildren();
    for (const agent of agents) {
      const row = document.createElement("tr");
      for (const value of [agent.name, agent.provider, agent.status,
        `${agent.spend_daily.toFixed(4)} / ${agent.cap_daily_usd}`,
        `${agent.spend_monthly.toFixed(4)} / ${agent.cap_monthly_usd}`]) {
        const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
      }
      const cell = document.createElement("td"), button = document.createElement("button");
      const action = agent.status === "active" ? "suspend" : "resume";
      button.textContent = action;
      button.onclick = async () => {
        try { await api(`/v1/agents/${encodeURIComponent(agent.id)}/${action}`, "POST"); await refresh(); }
        catch (error) { el("status").textContent = error.message; }
      };
      cell.append(button); row.append(cell); el("agents").append(row);
    }
    const {rows} = await api("/v1/audit");
    el("audit").textContent = rows.map(row => JSON.stringify(JSON.parse(row.row_json), null, 2)).join("\n");
    el("status").textContent = "Updated";
  } catch (error) { el("status").textContent = error.message; }
}
el("login").onsubmit = event => { event.preventDefault(); refresh(); };
el("verify").onclick = async () => {
  try { const result = await api("/v1/audit/verify"); el("status").textContent = result.ok ? "Audit chain verified" : "Audit chain verification FAILED"; }
  catch (error) { el("status").textContent = error.message; }
};
'''
