// DAEMON Engineering Solutions — Cloudflare Worker
// Public lead intake is stored in D1. Admin access uses a signed, HttpOnly session cookie.
const SESSION_SECONDS = 12 * 60 * 60;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if ((path === "/admin" || path === "/admin/") && request.method === "GET") {
      return env.ASSETS.fetch(new Request(new URL("/admin.html", request.url), request));
    }
    if (path === "/api/health" && request.method === "GET") {
      return json({ ok: true, lead_storage_configured: Boolean(env.DB), email_notifications: "disabled" });
    }
    if (path === "/api/preflight" && request.method === "POST") return createPreflight(request, env);
    if (path.startsWith("/api/receipts/") && request.method === "GET") return getReceipt(request, env, path);
    if (path === "/api/approvals" && request.method === "POST") return recordApproval(request, env);
    if (path === "/api/deployments" && request.method === "POST") {
      return json({ error: "Deployment adapters are not configured. No infrastructure change was executed.", deployment_enabled: false }, 501);
    }
    if (path === "/api/leads" && request.method === "POST") return handleLead(request, env);
    if (path === "/api/admin/login" && request.method === "POST") return adminLogin(request, env);
    if (path === "/api/admin/session" && request.method === "GET") {
      const valid = await hasAdminSession(request, env);
      return json({ authenticated: valid });
    }
    if (path === "/api/admin/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store",
          "Set-Cookie": "daemon_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }
      });
    }
    if (path === "/api/admin/receipts" && request.method === "GET") {
      if (!await hasAdminSession(request, env)) return json({ error: "Unauthorized." }, 401);
      if (!env.DB) return json({ error: "D1 is not configured yet." }, 503);
      const result = await env.DB.prepare("SELECT id, status, receipt_json, created_at FROM receipts ORDER BY created_at DESC LIMIT 100").all();
      return json({ receipts: (result.results || []).map(row => ({ id: row.id, status: row.status, created_at: row.created_at, receipt: JSON.parse(row.receipt_json) })) });
    }
    if (path === "/api/admin/leads" && request.method === "GET") {
      if (!await hasAdminSession(request, env)) return json({ error: "Unauthorized." }, 401);
      if (!env.DB) return json({ error: "D1 is not configured yet." }, 503);
      const result = await env.DB.prepare(
        "SELECT id, name, email, company, request_type, pain, status, created_at FROM leads ORDER BY id DESC LIMIT 250"
      ).all();
      return json({ leads: result.results || [] });
    }
    if (path === "/api/admin/leads/status" && request.method === "PATCH") {
      if (!await hasAdminSession(request, env)) return json({ error: "Unauthorized." }, 401);
      if (!env.DB) return json({ error: "D1 is not configured yet." }, 503);
      const body = await readJson(request);
      const id = Number(body?.id);
      const status = String(body?.status || "");
      if (!Number.isInteger(id) || id < 1 || !["new", "contacted", "qualified", "closed"].includes(status)) {
        return json({ error: "Invalid lead status update." }, 400);
      }
      await env.DB.prepare("UPDATE leads SET status = ? WHERE id = ?").bind(status, id).run();
      return json({ ok: true });
    }
    return env.ASSETS.fetch(request);
  }
};

async function createPreflight(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origin not allowed." }, 403);
  if (!env.DB) return json({ error: "Receipt storage is not configured." }, 503);
  if (!(request.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) return json({ error: "JSON required." }, 415);
  const body = await readJson(request);
  const manifest = String(body?.manifest || "");
  if (!manifest.trim() || manifest.length > 20000) return json({ error: "Provide a manifest between 1 and 20,000 characters." }, 400);
  const lower = manifest.toLowerCase();
  const findings = [];
  const add = (severity, code, title, recommendation) => findings.push({ severity, code, title, recommendation });
  if (/privileged:\s*true/.test(lower)) add("high", "PRIVILEGED_CONTAINER", "Privileged container enabled", "Review whether host-level privileges are required.");
  if (/runasnonroot:\s*false/.test(lower) || /runasuser:\s*0\b/.test(lower)) add("high", "ROOT_CONTAINER", "Container may run as root", "Use a non-root identity where supported.");
  if (/hostpath:/.test(lower)) add("high", "HOST_PATH", "HostPath volume detected", "Review host filesystem exposure and mount scope.");
  if (/image:\s*[^\n]+:latest\b/.test(lower)) add("medium", "MUTABLE_IMAGE_TAG", "Mutable image tag detected", "Pin an image version or digest and verify provenance.");
  if (/nodeport|loadbalancer|externalips:/.test(lower)) add("medium", "PUBLIC_SERVICE", "Potentially exposed service", "Review ingress, network policy and external access.");
  if (/allowprivilegeescalation:\s*true/.test(lower)) add("medium", "PRIVILEGE_ESCALATION", "Privilege escalation allowed", "Set allowPrivilegeEscalation to false where compatible.");
  if (!/resources:/.test(lower) && /kind:\s*(deployment|pod|statefulset)/.test(lower)) add("medium", "MISSING_RESOURCES", "Resource settings not detected", "Define CPU and memory requests and evaluate limits.");
  if (!findings.length) add("info", "NO_MATCHING_PATTERNS", "No listed patterns detected", "This does not establish that the manifest is secure.");
  const score = Math.max(0, 100 - findings.reduce((n, f) => n + (f.severity === "high" ? 25 : f.severity === "medium" ? 12 : 0), 0));
  const id = crypto.randomUUID();
  const receipt = {
    schema: "daemon-ace.receipt-of-safety.v1",
    id,
    record_type: "server_recorded_heuristic_preflight",
    created_at: new Date().toISOString(),
    status: "PENDING_REVIEW",
    analysis: { mode: "text_pattern_heuristics", score, findings, manifest_bytes: new TextEncoder().encode(manifest).length },
    scope: { live_cluster_connected: false, tests_executed: false, production_change_authorized: false },
    proposed_diff_available: false,
    limitations: ["Heuristic text checks only; not a YAML parser", "No cluster connection or live scan", "No vulnerability scanner", "No Helm, Kustomize or template resolution", "Not a security certification"]
  };
  await env.DB.prepare("INSERT INTO receipts (id, status, receipt_json, created_at) VALUES (?, 'pending', ?, datetime('now'))").bind(id, JSON.stringify(receipt)).run();
  return json({ ok: true, receipt_id: id, receipt });
}

async function getReceipt(request, env, path) {
  if (!env.DB) return json({ error: "Receipt storage is not configured." }, 503);
  const id = path.slice("/api/receipts/".length);
  if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Receipt not found." }, 404);
  const row = await env.DB.prepare("SELECT receipt_json FROM receipts WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Receipt not found." }, 404);
  return json({ receipt: JSON.parse(row.receipt_json) });
}

async function recordApproval(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origin not allowed." }, 403);
  if (!await hasAdminSession(request, env)) return json({ error: "An authenticated dashboard session is required." }, 401);
  if (!env.DB) return json({ error: "Receipt storage is not configured." }, 503);
  const body = await readJson(request);
  const id = String(body?.receipt_id || "");
  const decision = String(body?.decision || "");
  const note = clean(body?.note || "", 1000);
  if (!/^[0-9a-f-]{36}$/i.test(id) || !["approved_for_manual_review", "rejected"].includes(decision)) return json({ error: "Invalid approval decision." }, 400);
  const row = await env.DB.prepare("SELECT id FROM receipts WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Receipt not found." }, 404);
  await env.DB.prepare("INSERT INTO approvals (receipt_id, decision, note, actor, created_at) VALUES (?, ?, ?, 'dashboard-session', datetime('now'))").bind(id, decision, note).run();
  await env.DB.prepare("UPDATE receipts SET status = ?, updated_at = datetime('now') WHERE id = ?").bind(decision === "rejected" ? "rejected" : "approved_for_manual_review", id).run();
  return json({ ok: true, decision, deployment_executed: false, message: "Decision recorded. This endpoint does not deploy infrastructure." });
}

async function handleLead(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origin not allowed." }, 403);
  if (!env.DB) return json({ error: "Lead storage is not configured." }, 503);
  if (!(request.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) {
    return json({ error: "JSON required." }, 415);
  }
  const body = await readJson(request);
  if (!body) return json({ error: "Invalid request." }, 400);
  if (String(body.website || "").trim()) return json({ ok: true }); // honeypot
  const name = clean(body.name, 120);
  const email = clean(body.email, 254).toLowerCase();
  const requestType = clean(body.requestType || "Pilot inquiry", 80);
  const isQuickExecutiveRequest = requestType === "Executive Brief + Capability Statement";
  const company = clean(body.company || (isQuickExecutiveRequest ? "Executive brief request" : ""), 160);
  const pain = clean(body.pain || (isQuickExecutiveRequest ? "Please send the DAEMON ACE Executive Brief and Capability Statement." : ""), 3000);
  if (!name || !company || !pain || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "Please complete all required fields with a valid email address." }, 400);
  }
  await env.DB.prepare(
    "INSERT INTO leads (name, email, company, request_type, pain, status, created_at) VALUES (?, ?, ?, ?, ?, 'new', datetime('now'))"
  ).bind(name, email, company, requestType, pain).run();
  return json({ ok: true, stored: true });
}

async function adminLogin(request, env) {
  if (!sameOrigin(request)) return json({ error: "Origin not allowed." }, 403);
  if (!env.DASHBOARD_PASSWORD) return json({ error: "Dashboard password is not configured." }, 503);
  const body = await readJson(request);
  const supplied = String(body?.password || "");
  if (!supplied || !(await constantTimeEqual(supplied, env.DASHBOARD_PASSWORD))) {
    return json({ error: "Incorrect password." }, 401);
  }
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const signature = await sign(String(expires), env.DASHBOARD_PASSWORD);
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store",
      "Set-Cookie": "daemon_admin=" + expires + "." + signature + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + SESSION_SECONDS }
  });
}

async function hasAdminSession(request, env) {
  if (!env.DASHBOARD_PASSWORD) return false;
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.split(";").map(x => x.trim()).find(x => x.startsWith("daemon_admin="));
  if (!match) return false;
  const token = match.slice("daemon_admin=".length);
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const expires = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  if (!/^\d+$/.test(expires) || Number(expires) < Math.floor(Date.now() / 1000)) return false;
  const expected = await sign(expires, env.DASHBOARD_PASSWORD);
  return constantTimeEqual(signature, expected);
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function constantTimeEqual(a, b) {
  const aa = new TextEncoder().encode(String(a)), bb = new TextEncoder().encode(String(b));
  let diff = aa.length ^ bb.length;
  const n = Math.max(aa.length, bb.length);
  for (let i = 0; i < n; i++) diff |= (aa[i] || 0) ^ (bb[i] || 0);
  return diff === 0;
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}
async function readJson(request) {
  try {
    const raw = await request.text();
    if (raw.length > 12000) return null;
    return JSON.parse(raw);
  } catch { return null; }
}
function clean(value, max) {
  return String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
