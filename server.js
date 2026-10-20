const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const root = __dirname;
const dataDir = process.env.DATA_DIR || root;
const logPath = path.join(dataDir, "visits.jsonl");

// MIME types for static assets
const mime = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".pdf": "application/pdf",
  ".ico": "image/x-icon"
};

// ==========================================
// OPTIONAL CLOUD PERSISTENCE (PostgreSQL)
// ==========================================
// If DATABASE_URL is set (e.g. Supabase, Neon, Render PostgreSQL),
// visitor data is permanently stored in the cloud database across redeploys!
let dbPool = null;
const dbUrl = process.env.DATABASE_URL;

if (dbUrl) {
  try {
    const { Pool } = require("pg");
    dbPool = new Pool({
      connectionString: dbUrl,
      ssl: dbUrl.includes("localhost") ? false : { rejectUnauthorized: false },
      connectionTimeoutMillis: 5000
    });

    dbPool.query(`
      CREATE TABLE IF NOT EXISTS portfolio_visits (
        id SERIAL PRIMARY KEY,
        time TIMESTAMPTZ NOT NULL,
        ip TEXT,
        page TEXT,
        user_agent TEXT,
        source TEXT,
        referrer TEXT,
        device TEXT,
        browser TEXT,
        location TEXT,
        vid TEXT,
        name TEXT
      );
    `).then(() => {
      console.log("Connected to PostgreSQL for persistent visitor tracking.");
    }).catch(err => {
      console.warn("PostgreSQL initialization warning (falling back to visits.jsonl):", err.message);
      dbPool = null;
    });
  } catch {
    // pg not installed locally, will use visits.jsonl
    dbPool = null;
  }
}

// ==========================================
// TRAFFIC SOURCE & REFERRER CLASSIFIER
// ==========================================
function parseSource(ref, referrer) {
  if (ref && String(ref).trim()) {
    const cleanRef = String(ref).trim().slice(0, 50);
    // Format common campaign tags
    if (/^linkedin/i.test(cleanRef)) return "LinkedIn";
    if (/^whatsapp/i.test(cleanRef)) return "WhatsApp";
    if (/^resume/i.test(cleanRef)) return "Resume Link";
    if (/^github/i.test(cleanRef)) return "GitHub";
    return cleanRef;
  }

  if (!referrer || typeof referrer !== "string") {
    return "Direct / Message";
  }

  try {
    const url = new URL(referrer);
    const host = url.hostname.toLowerCase();
    if (host.includes("linkedin.com") || host.includes("lnkd.in")) return "LinkedIn";
    if (host.includes("whatsapp.com") || host.includes("wa.me")) return "WhatsApp";
    if (host.includes("instagram.com")) return "Instagram";
    if (host.includes("github.com")) return "GitHub";
    if (host.includes("google.")) return "Google";
    if (host.includes("t.co") || host.includes("twitter.com") || host.includes("x.com")) return "X / Twitter";
    if (host.includes("youtube.com")) return "YouTube";
    if (host.includes("facebook.com")) return "Facebook";
    if (host.includes("reddit.com")) return "Reddit";
    return host.replace(/^www\./, "");
  } catch {
    return "Direct / Message";
  }
}

// ==========================================
// USER-AGENT & DEVICE PARSER
// ==========================================
function describeAgent(ua) {
  ua = String(ua || "");

  let os = "Other OS";
  let deviceType = "Desktop";

  if (/Android/i.test(ua)) {
    os = "Android";
    deviceType = /Mobile/i.test(ua) ? "Mobile" : "Tablet";
  } else if (/iPhone/i.test(ua)) {
    os = "iOS";
    deviceType = "Mobile";
  } else if (/iPad/i.test(ua)) {
    os = "iPadOS";
    deviceType = "Tablet";
  } else if (/Windows NT/i.test(ua)) {
    os = "Windows";
    deviceType = "Desktop";
  } else if (/Mac OS X|Macintosh/i.test(ua)) {
    os = "macOS";
    deviceType = "Desktop";
  } else if (/Linux/i.test(ua)) {
    os = "Linux";
    deviceType = "Desktop";
  }

  let browser = "Browser";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/OPR\/|Opera/i.test(ua)) browser = "Opera";
  else if (/Chrome\/|CriOS/i.test(ua)) browser = "Chrome";
  else if (/Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Safari\//i.test(ua)) browser = "Safari";

  return {
    os,
    browser,
    deviceType,
    summary: `${browser} on ${os} (${deviceType})`
  };
}

// Bot and crawler detector
const BOT_PATTERN = /bot|crawl|spider|slurp|facebookexternalhit|headless|monitor|uptime|pingdom|lighthouse|curl\/|wget|python-requests|axios|node-fetch|go-http-client|okhttp/i;

// In-memory rate limiter
function rateLimited(store, key, max, windowMs) {
  const now = Date.now();
  const entry = store.get(key);
  if (!entry || now - entry.start > windowMs) {
    store.set(key, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > max;
}

const visitHits = new Map();
const authFails = new Map();

setInterval(() => {
  const cutoff = Date.now() - 60 * 60 * 1000;
  for (const store of [visitHits, authFails]) {
    for (const [key, entry] of store) if (entry.start < cutoff) store.delete(key);
  }
}, 10 * 60 * 1000).unref();

// Geolocation lookup with cache
const geoCache = new Map();
const privateIp = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80|fc|fd)/i;

async function lookupGeo(ip) {
  if (!ip || privateIp.test(ip) || ip === "Not provided") return null;
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}?fields=success,city,country`, {
      signal: AbortSignal.timeout(2500)
    });
    const data = await res.json();
    const loc = data.success && (data.city || data.country)
      ? [data.city, data.country].filter(Boolean).join(", ")
      : null;
    geoCache.set(ip, loc);
    return loc;
  } catch {
    return null;
  }
}

function getClientIp(req) {
  let ip = req.socket.remoteAddress || "Not provided";

  // Automatically detect client IP when deployed on Render or behind a proxy
  if (process.env.TRUST_PROXY === "1" || process.env.RENDER) {
    const forwardedFor = req.headers["x-forwarded-for"];
    if (typeof forwardedFor === "string") {
      const forwardedIps = forwardedFor.split(",").map(v => v.trim()).filter(Boolean);
      if (forwardedIps.length) ip = forwardedIps[0];
    }
  }

  if (ip.startsWith("::ffff:")) ip = ip.substring(7);
  return ip;
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return "";
}

function getOwnerPassword() {
  return process.env.OWNER_PASSWORD || "admin";
}

function ownerToken() {
  return crypto.createHash("sha256")
    .update("portfolio-owner:" + getOwnerPassword())
    .digest("hex");
}

function isOwnerBrowser(req) {
  const actual = Buffer.from(getCookie(req, "portfolio_owner"));
  const expected = Buffer.from(ownerToken());
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function ownerCookie(req) {
  const secure = (process.env.TRUST_PROXY === "1" || process.env.RENDER) &&
    req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  return `portfolio_owner=${ownerToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000${secure}`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function send(res, status, contentType, body, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    ...extraHeaders
  });
  res.end(body);
}

function ownerAuthorized(req, res) {
  const password = getOwnerPassword();
  const ip = getClientIp(req);

  const blocked = (authFails.get(ip)?.count || 0) >= 5 &&
    Date.now() - authFails.get(ip).start < 15 * 60 * 1000;
  if (blocked) {
    send(res, 429, "text/plain; charset=utf-8", "Too many failed attempts. Try again in 15 minutes.");
    return false;
  }

  if (isOwnerBrowser(req)) {
    return true;
  }

  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Basic ")) {
    res.writeHead(401, {
      "WWW-Authenticate": 'Basic realm="Portfolio Owner Dashboard"',
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end("Enter username owner and your dashboard password.");
    return false;
  }

  const credentials = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
  const colonIndex = credentials.indexOf(":");
  const user = colonIndex !== -1 ? credentials.slice(0, colonIndex) : "";
  const pass = colonIndex !== -1 ? credentials.slice(colonIndex + 1) : "";

  const expectedUser = process.env.OWNER_USER || "owner";
  const userBuf = Buffer.from(user.padEnd(64).slice(0, 64));
  const expUserBuf = Buffer.from(expectedUser.padEnd(64).slice(0, 64));
  const passBuf = Buffer.from(pass.padEnd(128).slice(0, 128));
  const expPassBuf = Buffer.from(password.padEnd(128).slice(0, 128));

  const userMatch = crypto.timingSafeEqual(userBuf, expUserBuf) && user.length === expectedUser.length;
  const passMatch = crypto.timingSafeEqual(passBuf, expPassBuf) && pass.length === password.length;

  if (!userMatch || !passMatch) {
    rateLimited(authFails, ip, 5, 15 * 60 * 1000);
    res.writeHead(401, {
      "WWW-Authenticate": 'Basic realm="Portfolio Owner Dashboard"',
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end("Invalid username or password.");
    return false;
  }

  authFails.delete(ip);
  return true;
}

// ==========================================
// READ & PERSIST VISITS
// ==========================================
function readVisitsFromFile() {
  try {
    if (!fs.existsSync(logPath)) return [];
    return fs.readFileSync(logPath, "utf8")
      .split("\n")
      .filter(Boolean)
      .map(line => {
        try {
          const item = JSON.parse(line);
          const agentInfo = describeAgent(item.userAgent);
          const loc = item.location || (item.city || item.country ? [item.city, item.country].filter(Boolean).join(", ") : null);
          const source = item.source || parseSource(item.ref, item.referrer);
          return {
            time: item.time,
            ip: item.ip,
            page: item.page || "/",
            userAgent: item.userAgent,
            device: item.device || agentInfo.os + " (" + agentInfo.deviceType + ")",
            browser: item.browser || agentInfo.browser,
            source: source,
            referrer: item.referrer || null,
            location: loc,
            vid: item.vid || item.ip,
            name: item.name || (item.ref && item.ref.startsWith("Introduced:") ? item.ref.replace(/^Introduced:\s*/, "") : null)
          };
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .slice(-500)
      .reverse();
  } catch {
    return [];
  }
}

async function getAllVisits() {
  if (dbPool) {
    try {
      const res = await dbPool.query(
        `SELECT time, ip, page, user_agent AS "userAgent", source, referrer, device, browser, location, vid, name
         FROM portfolio_visits
         ORDER BY time DESC
         LIMIT 500`
      );
      if (res.rows.length > 0) {
        return res.rows.map(r => ({
          ...r,
          time: new Date(r.time).toISOString()
        }));
      }
    } catch (err) {
      console.warn("Database read warning, using local file:", err.message);
    }
  }
  return readVisitsFromFile();
}

async function recordVisitEntry(entry) {
  // 1. Append to local visits.jsonl file
  try {
    fs.appendFileSync(logPath, JSON.stringify(entry) + "\n", "utf8");
  } catch (err) {
    console.error("Local file write error:", err.message);
  }

  // 2. Persist to PostgreSQL if connected
  if (dbPool) {
    try {
      await dbPool.query(
        `INSERT INTO portfolio_visits (time, ip, page, user_agent, source, referrer, device, browser, location, vid, name)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          entry.time,
          entry.ip,
          entry.page,
          entry.userAgent,
          entry.source,
          entry.referrer,
          entry.device,
          entry.browser,
          entry.location,
          entry.vid,
          entry.name
        ]
      );
    } catch (err) {
      console.error("Database insert error:", err.message);
    }
  }
}

// ==========================================
// HTTP SERVER & ROUTING
// ==========================================
const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, "http://localhost");
  } catch {
    return send(res, 400, "text/plain; charset=utf-8", "Bad request");
  }

  // ------------------------------------------
  // 1. OWNER DASHBOARD ROUTE: /owner
  // ------------------------------------------
  if (url.pathname === "/owner") {
    if (req.method !== "GET") {
      return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
    }

    if (!ownerAuthorized(req, res)) return;

    const visits = await getAllVisits();
    const totalVisits = visits.length;
    const uniqueVisitors = new Set(visits.map(v => v.vid || v.ip)).size;
    const last24h = visits.filter(v => Date.now() - Date.parse(v.time) < 24 * 60 * 60 * 1000).length;

    // Traffic sources breakdown
    const sourceCounts = {};
    const deviceCounts = { Mobile: 0, Desktop: 0, Tablet: 0 };

    for (const v of visits) {
      const src = v.source || "Direct / Message";
      sourceCounts[src] = (sourceCounts[src] || 0) + 1;

      const dev = v.device || "";
      if (dev.includes("Mobile")) deviceCounts.Mobile++;
      else if (dev.includes("Tablet")) deviceCounts.Tablet++;
      else deviceCounts.Desktop++;
    }

    const sortedSources = Object.entries(sourceCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const sourceBadgesHtml = sortedSources.map(([src, count]) => {
      const percent = totalVisits > 0 ? Math.round((count / totalVisits) * 100) : 0;
      let icon = "🔗";
      if (src.includes("LinkedIn")) icon = "💼";
      else if (src.includes("WhatsApp")) icon = "💬";
      else if (src.includes("Google")) icon = "🔍";
      else if (src.includes("Instagram")) icon = "📸";
      else if (src.includes("GitHub")) icon = "🐙";
      else if (src.includes("Resume")) icon = "📄";
      return `<span class="source-pill">${icon} <b>${escapeHtml(src)}</b> <small>${count} (${percent}%)</small></span>`;
    }).join("") || `<span style="color:var(--muted)">No traffic sources recorded yet.</span>`;

    const rows = visits.map(v => {
      let displayName = "🌐 Anonymous Visitor";
      let nameClass = "";
      if (v.name) {
        displayName = `👤 ${escapeHtml(v.name)}`;
        nameClass = "is-introduced";
      }

      let sourceIcon = "🔗";
      const src = v.source || "Direct / Message";
      if (src.includes("LinkedIn")) sourceIcon = "💼";
      else if (src.includes("WhatsApp")) sourceIcon = "💬";
      else if (src.includes("Google")) sourceIcon = "🔍";
      else if (src.includes("Instagram")) sourceIcon = "📸";
      else if (src.includes("GitHub")) sourceIcon = "🐙";

      const loc = v.location ? `📍 ${escapeHtml(v.location)}` : "—";
      const dev = escapeHtml(v.device || "Desktop");
      const browser = escapeHtml(v.browser || "Browser");

      return `
      <tr>
        <td class="${nameClass}"><strong>${displayName}</strong></td>
        <td><time datetime="${escapeHtml(v.time)}">${escapeHtml(v.time)}</time></td>
        <td><span class="source-tag">${sourceIcon} ${escapeHtml(src)}</span></td>
        <td>${loc}</td>
        <td>${dev} · ${browser}</td>
        <td><code>${escapeHtml(v.page)}</code></td>
        <td><code class="ip-code">${escapeHtml(v.ip)}</code></td>
      </tr>
      `;
    }).join("");

    const storageStatus = dbPool ? "Cloud Database (PostgreSQL)" : "Local Storage (visits.jsonl)";

    const pageHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Portfolio Visitor Intelligence | Owner Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Source+Sans+3:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#070b16;
  --card:#0f172a;
  --border:#263556;
  --primary:#8b5cf6;
  --cyan:#06b6d4;
  --lime:#a3e635;
  --text:#f8fafc;
  --muted:#94a3b8;
}
*{box-sizing:border-box}
body{
  margin:0;
  background:radial-gradient(ellipse at 15% 10%, #1e1548 0, transparent 40%),
             radial-gradient(ellipse at 85% 20%, #06313f 0, transparent 35%),
             var(--bg);
  color:var(--text);
  font:15px/1.6 'Source Sans 3',system-ui,sans-serif;
  min-height:100vh;
}
main{max-width:1180px;width:92%;margin:40px auto 60px}
.header{
  display:flex;
  justify-content:space-between;
  align-items:center;
  flex-wrap:wrap;
  gap:16px;
  padding-bottom:20px;
  border-bottom:1px solid var(--border);
}
.brand{display:flex;align-items:center;gap:10px}
.badge-live{
  display:inline-flex;
  align-items:center;
  gap:7px;
  font-size:11px;
  font-weight:700;
  color:var(--lime);
  background:#a3e63518;
  border:1px solid #a3e63533;
  padding:4px 10px;
  border-radius:999px;
  letter-spacing:0.05em;
}
.pulse{
  width:8px;
  height:8px;
  border-radius:50%;
  background:var(--lime);
  box-shadow:0 0 8px var(--lime);
  animation:pulse 2s infinite;
}
@keyframes pulse{
  0%,100%{opacity:1;transform:scale(1)}
  50%{opacity:.5;transform:scale(1.2)}
}
h1{font-family:'Outfit',sans-serif;font-size:clamp(1.8rem,4vw,2.4rem);margin:6px 0 0;font-weight:750}
.header-actions{display:flex;align-items:center;gap:10px}
.btn{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:8px 16px;
  background:#1e293b;
  color:#cbd5e1;
  text-decoration:none;
  border:1px solid var(--border);
  border-radius:8px;
  font-size:13px;
  font-weight:600;
  transition:.2s;
  cursor:pointer;
}
.btn:hover{background:#334155;color:#fff}
.btn-primary{background:var(--primary);color:#fff;border-color:var(--primary)}
.btn-primary:hover{background:#7c3aed}

.stats-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
  gap:14px;
  margin:25px 0 25px;
}
.stat-card{
  background:linear-gradient(145deg, #131d36, #0e162b);
  border:1px solid var(--border);
  border-radius:14px;
  padding:20px;
  position:relative;
  overflow:hidden;
}
.stat-card::before{
  content:"";
  position:absolute;
  top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--primary),var(--cyan));
}
.stat-card b{font-family:'Outfit',sans-serif;display:block;font-size:2.2rem;font-weight:800;color:#fff;line-height:1.1}
.stat-card span{color:var(--muted);font-size:12px;font-weight:700;letter-spacing:.05em;margin-top:6px;display:block}

.breakdown-section{
  background:#0d1427;
  border:1px solid var(--border);
  border-radius:14px;
  padding:18px 22px;
  margin-bottom:30px;
}
.breakdown-title{font-size:13px;font-weight:700;color:#93c5fd;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px}
.sources-list{display:flex;flex-wrap:wrap;gap:10px}
.source-pill{
  background:#1e293b;
  border:1px solid #334155;
  border-radius:999px;
  padding:5px 12px;
  font-size:13px;
  display:inline-flex;
  align-items:center;
  gap:6px;
}
.source-pill b{color:#fff}
.source-pill small{color:var(--cyan);font-weight:600}

.table-header-row{
  display:flex;
  justify-content:space-between;
  align-items:center;
  flex-wrap:wrap;
  gap:12px;
  margin-bottom:14px;
}
.table-header-row h2{font-family:'Outfit',sans-serif;font-size:1.3rem;margin:0}
.search-box{
  background:#0e162b;
  border:1px solid var(--border);
  color:#fff;
  padding:9px 14px;
  border-radius:8px;
  font-size:13px;
  width:280px;
}
.search-box:focus{outline:none;border-color:var(--primary)}

.table-wrap{
  overflow-x:auto;
  border:1px solid var(--border);
  border-radius:14px;
  background:#0d1427;
}
table{border-collapse:collapse;width:100%;min-width:880px}
th,td{text-align:left;padding:13px 16px;border-bottom:1px solid #1e293b}
th{color:#93c5fd;background:#111a30;font-size:12px;letter-spacing:.05em;text-transform:uppercase;font-weight:700}
td{font-size:13.5px}
tbody tr:hover{background:#131c3566}

.is-introduced strong{color:#a3e635}
.source-tag{
  background:#1e293b;
  padding:3px 8px;
  border-radius:6px;
  font-size:12px;
  font-weight:600;
  border:1px solid #334155;
}
code{background:#1e293b;color:#a5b4fc;padding:2px 6px;border-radius:4px;font-size:12px}
.ip-code{color:#cbd5e1}

.footer-info{
  margin-top:24px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  flex-wrap:wrap;
  gap:12px;
  font-size:13px;
  color:var(--muted);
}
.status-pill{
  background:#131c36;
  border:1px solid var(--border);
  padding:6px 12px;
  border-radius:6px;
  display:inline-flex;
  align-items:center;
  gap:6px;
}
</style>
</head>
<body>
<main>
  <div class="header">
    <div>
      <div class="brand">
        <span class="badge-live"><span class="pulse"></span> LIVE TRAFFIC</span>
        <span style="font-size:12px;color:var(--muted);font-weight:600">SHREYA'S PRIVATE DASHBOARD</span>
      </div>
      <h1>Portfolio Visitors & Traffic</h1>
    </div>
    <div class="header-actions">
      <a href="/owner/export.csv" class="btn" title="Download complete visitor logs as CSV">📥 Export CSV</a>
      <a href="/" class="btn btn-primary">← View Portfolio</a>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <b>${totalVisits}</b>
      <span>TOTAL VISITS RECORDED</span>
    </div>
    <div class="stat-card">
      <b>${uniqueVisitors}</b>
      <span>UNIQUE VISITORS</span>
    </div>
    <div class="stat-card">
      <b>${last24h}</b>
      <span>ACTIVE LAST 24 HOURS</span>
    </div>
    <div class="stat-card">
      <b>${sortedSources[0] ? escapeHtml(sortedSources[0][0]) : "Direct"}</b>
      <span>TOP TRAFFIC SOURCE</span>
    </div>
  </div>

  <div class="breakdown-section">
    <div class="breakdown-title">Top Traffic Sources & Referrals</div>
    <div class="sources-list">
      ${sourceBadgesHtml}
    </div>
  </div>

  <div class="table-header-row">
    <h2>Visitor Activity Feed</h2>
    <input type="text" id="filter-input" class="search-box" placeholder="Filter by name, source, location, IP...">
  </div>

  <div class="table-wrap">
    <table id="visitors-table">
      <thead>
        <tr>
          <th>Visitor</th>
          <th>Time (Local)</th>
          <th>Source / Referrer</th>
          <th>Location</th>
          <th>Device & Browser</th>
          <th>Page</th>
          <th>IP Address</th>
        </tr>
      </thead>
      <tbody>
        ${rows || '<tr><td colspan="7" style="text-align:center;padding:35px;color:var(--muted)">No visits recorded yet. Share your portfolio link to start tracking!</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="footer-info">
    <div class="status-pill">
      <span>💾 Storage Backend:</span> <b>${storageStatus}</b>
    </div>
    <div>
      Protected with Basic Auth. Visits from your owner browser are automatically filtered out.
    </div>
  </div>
</main>

<script>
// Format timestamps into local browser time
document.querySelectorAll("time[datetime]").forEach(function(el) {
  var d = new Date(el.getAttribute("datetime"));
  if (!isNaN(d)) el.textContent = d.toLocaleString();
});

// Real-time table filter search
var searchInput = document.getElementById("filter-input");
if (searchInput) {
  searchInput.addEventListener("input", function() {
    var query = this.value.toLowerCase().trim();
    document.querySelectorAll("#visitors-table tbody tr").forEach(function(row) {
      var text = row.textContent.toLowerCase();
      row.style.display = (!query || text.indexOf(query) !== -1) ? "" : "none";
    });
  });
}
</script>
</body>
</html>`;

    return send(res, 200, "text/html; charset=utf-8", pageHtml, {
      "Set-Cookie": ownerCookie(req)
    });
  }

  // ------------------------------------------
  // 2. EXPORT VISITOR DATA TO CSV: /owner/export.csv
  // ------------------------------------------
  if (url.pathname === "/owner/export.csv") {
    if (req.method !== "GET") {
      return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
    }

    if (!ownerAuthorized(req, res)) return;

    const visits = await getAllVisits();
    const csvHeader = "Time,Visitor Name,Source,Location,Device,Browser,Page,IP Address,Referrer URL\r\n";
    const escapeCsv = v => `"${String(v ?? "").replace(/"/g, '""')}"`;

    const csvRows = visits.map(v => [
      escapeCsv(v.time),
      escapeCsv(v.name || "Anonymous"),
      escapeCsv(v.source || "Direct"),
      escapeCsv(v.location || ""),
      escapeCsv(v.device || ""),
      escapeCsv(v.browser || ""),
      escapeCsv(v.page || "/"),
      escapeCsv(v.ip || ""),
      escapeCsv(v.referrer || "")
    ].join(",")).join("\r\n");

    return send(res, 200, "text/csv; charset=utf-8", csvHeader + csvRows, {
      "Content-Disposition": 'attachment; filename="portfolio-visitors.csv"'
    });
  }

  // ------------------------------------------
  // 3. RECORD VISIT: /api/visit
  // ------------------------------------------
  if (url.pathname === "/api/visit") {
    const json = (status, body) =>
      send(res, status, "application/json; charset=utf-8", JSON.stringify(body));

    const userAgent = String(req.headers["user-agent"] || "Not provided").slice(0, 300);

    if (isOwnerBrowser(req)) return json(200, { recorded: false, reason: "owner" });
    if (BOT_PATTERN.test(userAgent)) return json(200, { recorded: false, reason: "bot" });

    const ip = getClientIp(req);

    if (rateLimited(visitHits, ip, 15, 60 * 1000)) {
      return json(429, { recorded: false, reason: "rate-limited" });
    }

    const processPayload = async (pagePath, referrer, refParam, vid) => {
      if (!pagePath || !pagePath.startsWith("/") || pagePath.length > 200) pagePath = "/";

      const agentInfo = describeAgent(userAgent);
      const source = parseSource(refParam, referrer);
      const location = await lookupGeo(ip);

      const entry = {
        time: new Date().toISOString(),
        ip,
        page: pagePath,
        userAgent,
        device: agentInfo.os + " (" + agentInfo.deviceType + ")",
        browser: agentInfo.browser,
        source,
        referrer: referrer ? String(referrer).slice(0, 300) : null,
        location,
        vid: vid || ip,
        name: null
      };

      await recordVisitEntry(entry);
      return json(200, { recorded: true });
    };

    if (req.method === "POST") {
      let bodyData = "";
      req.on("data", chunk => {
        bodyData += chunk;
        if (bodyData.length > 10000) req.destroy();
      });
      req.on("end", async () => {
        try {
          const payload = JSON.parse(bodyData || "{}");
          await processPayload(payload.page, payload.referrer, payload.ref, payload.vid);
        } catch {
          await processPayload("/", "", "", "");
        }
      });
      return;
    }

    if (req.method === "GET") {
      const pagePath = url.searchParams.get("page") || "/";
      const referrer = url.searchParams.get("referrer") || req.headers.referer || "";
      const refParam = url.searchParams.get("ref") || "";
      const vid = url.searchParams.get("vid") || "";
      return await processPayload(pagePath, referrer, refParam, vid);
    }

    return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
  }

  // ------------------------------------------
  // 4. SELF-IDENTIFY VISIT: /api/visit/identify
  // ------------------------------------------
  if (url.pathname === "/api/visit/identify") {
    if (req.method !== "POST") {
      return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
    }

    const json = (status, body) =>
      send(res, status, "application/json; charset=utf-8", JSON.stringify(body));

    let bodyData = "";
    req.on("data", chunk => {
      bodyData += chunk;
      if (bodyData.length > 10000) req.destroy();
    });

    req.on("end", async () => {
      try {
        const payload = JSON.parse(bodyData || "{}");
        const rawName = String(payload.name || "").trim().slice(0, 80);
        if (!rawName) return json(400, { success: false, error: "Name is required" });

        const ip = getClientIp(req);
        const userAgent = String(req.headers["user-agent"] || "Not provided").slice(0, 300);
        const agentInfo = describeAgent(userAgent);
        const pagePath = (payload.page || "/").split(/[?#]/)[0] || "/";
        const source = parseSource(payload.ref, payload.referrer);
        const location = await lookupGeo(ip);

        const entry = {
          time: new Date().toISOString(),
          ip,
          page: pagePath,
          userAgent,
          device: agentInfo.os + " (" + agentInfo.deviceType + ")",
          browser: agentInfo.browser,
          source,
          referrer: payload.referrer ? String(payload.referrer).slice(0, 300) : null,
          location,
          vid: payload.vid || ip,
          name: rawName
        };

        await recordVisitEntry(entry);
        return json(200, { success: true, recorded: true });
      } catch (err) {
        return json(400, { success: false, error: "Invalid JSON" });
      }
    });
    return;
  }

  // ------------------------------------------
  // 5. PUBLIC PORTFOLIO STATIC FILE SERVING
  // ------------------------------------------
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return send(res, 400, "text/plain; charset=utf-8", "Bad URL");
  }

  if (pathname === "/") pathname = "/index.html";

  const publicFiles = new Set(["/index.html", "/styles.css", "/script.js", "/robots.txt"]);
  const publicFolders = ["/assets/", "/images/"];
  const isPublic = publicFiles.has(pathname) || publicFolders.some(f => pathname.startsWith(f));

  if (!isPublic) {
    return send(res, 404, "text/plain; charset=utf-8", "Not found");
  }

  const file = path.resolve(root, "." + pathname);
  if (!file.startsWith(root + path.sep)) {
    return send(res, 403, "text/plain; charset=utf-8", "Forbidden");
  }

  fs.readFile(file, (err, body) => {
    if (err) {
      return send(res, 404, "text/plain; charset=utf-8", "Not found");
    }

    return send(
      res,
      200,
      mime[path.extname(file).toLowerCase()] || "application/octet-stream",
      body
    );
  });
});

// ==========================================
// PORT LISTENER (Explicit 0.0.0.0 for Render)
// ==========================================
const targetPort = Number(process.env.PORT) || 3000;

function listenOnPort(port) {
  server.once("error", error => {
    if (error.code === "EADDRINUSE" && !process.env.RENDER && port < targetPort + 20) {
      console.log(`Port ${port} is busy; trying ${port + 1}...`);
      return listenOnPort(port + 1);
    }
    console.error("Could not start server:", error.message);
    process.exitCode = 1;
  });

  // Explicitly listen on 0.0.0.0 so Render and external visitors can connect
  server.listen(port, "0.0.0.0", () => {
    const address = server.address();
    console.log(`Portfolio running at http://localhost:${address.port}`);
    console.log(`Owner dashboard available at http://localhost:${address.port}/owner`);
  });
}

listenOnPort(targetPort);
