const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ==========================================
// 1. AUTO-LOAD .ENV CONFIGURATION
// ==========================================
(function loadEnvFile() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;

  // Use Node 20.12+ built-in process.loadEnvFile if available
  try {
    if (typeof process.loadEnvFile === "function") {
      process.loadEnvFile(envPath);
      return;
    }
  } catch {}

  // Graceful fallback parser for earlier Node versions
  try {
    const content = fs.readFileSync(envPath, "utf8");
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const eqIdx = line.indexOf("=");
      if (eqIdx > 0) {
        const key = line.slice(0, eqIdx).trim();
        let val = line.slice(eqIdx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        if (process.env[key] === undefined) {
          process.env[key] = val;
        }
      }
    }
  } catch {}
})();

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
// 2. CREDENTIALS & SECURITY CONFIGURATION
// ==========================================
function getOwnerUsername() {
  return process.env.OWNER_USERNAME || process.env.OWNER_USER || "admin";
}

function getOwnerPassword() {
  return process.env.OWNER_PASSWORD || "admin";
}

// Constant-time string comparison preventing timing attacks
function safeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const hashA = crypto.createHash("sha256").update(a).digest();
  const hashB = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// Session authentication token tied to current username & password
function getSessionToken() {
  return crypto
    .createHash("sha256")
    .update(`portfolio-owner:${getOwnerUsername()}:${getOwnerPassword()}`)
    .digest("hex");
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0 && part.slice(0, idx).trim() === name) {
      return part.slice(idx + 1).trim();
    }
  }
  return "";
}

function isSessionValid(req) {
  const token = getCookie(req, "portfolio_session") || getCookie(req, "portfolio_owner");
  if (!token) return false;
  return safeCompare(token, getSessionToken());
}

function checkBasicAuth(req) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Basic ")) return false;
  try {
    const creds = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    const colonIdx = creds.indexOf(":");
    if (colonIdx === -1) return false;
    const user = creds.slice(0, colonIdx);
    const pass = creds.slice(colonIdx + 1);
    return safeCompare(user, getOwnerUsername()) && safeCompare(pass, getOwnerPassword());
  } catch {
    return false;
  }
}

function isOwnerAuthorized(req) {
  return isSessionValid(req) || checkBasicAuth(req);
}

function sessionCookieHeaders(req) {
  const isHttps = req.headers["x-forwarded-proto"] === "https" ||
    (process.env.RENDER && process.env.RENDER !== "false");
  const secureFlag = isHttps ? "; Secure" : "";
  const token = getSessionToken();
  return [
    `portfolio_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secureFlag}`,
    `portfolio_owner=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secureFlag}`
  ];
}

function clearCookieHeaders(req) {
  const isHttps = req?.headers?.["x-forwarded-proto"] === "https" ||
    (process.env.RENDER && process.env.RENDER !== "false");
  const secureFlag = isHttps ? "; Secure" : "";
  return [
    `portfolio_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag}`,
    `portfolio_owner=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag}`
  ];
}

// ==========================================
// 3. OPTIONAL CLOUD PERSISTENCE (PostgreSQL)
// ==========================================
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
        name TEXT,
        is_owner BOOLEAN DEFAULT FALSE
      );
      ALTER TABLE portfolio_visits ADD COLUMN IF NOT EXISTS is_owner BOOLEAN DEFAULT FALSE;
    `).then(() => {
      console.log("Connected to PostgreSQL for persistent visitor tracking.");
    }).catch(err => {
      console.warn("PostgreSQL initialization warning (falling back to visits.jsonl):", err.message);
      dbPool = null;
    });
  } catch {
    dbPool = null;
  }
}

// ==========================================
// 4. IP DETECTION & GEOLOCATION
// ==========================================
function cleanIp(ip) {
  if (!ip) return "Not provided";
  let cleaned = String(ip).trim();
  if (cleaned.startsWith("::ffff:")) {
    cleaned = cleaned.substring(7);
  }
  if (cleaned === "::1") {
    cleaned = "127.0.0.1";
  }
  return cleaned;
}

function getClientIp(req) {
  const trustProxy = process.env.TRUST_PROXY !== "0";

  if (trustProxy) {
    // 1. Cloudflare header
    const cf = req.headers["cf-connecting-ip"];
    if (typeof cf === "string" && cf.trim()) return cleanIp(cf);

    // 2. Nginx / reverse proxy / Render x-real-ip
    const realIp = req.headers["x-real-ip"];
    if (typeof realIp === "string" && realIp.trim()) return cleanIp(realIp);

    // 3. Standard x-forwarded-for (first IP in chain is original client)
    const forwardedFor = req.headers["x-forwarded-for"];
    if (typeof forwardedFor === "string" && forwardedFor.trim()) {
      const parts = forwardedFor.split(",").map(v => v.trim()).filter(Boolean);
      if (parts.length > 0) return cleanIp(parts[0]);
    }

    // 4. x-client-ip
    const clientIp = req.headers["x-client-ip"];
    if (typeof clientIp === "string" && clientIp.trim()) return cleanIp(clientIp);
  }

  // 5. Direct socket connection
  return cleanIp(req.socket?.remoteAddress);
}

const geoCache = new Map();
const privateIpPattern = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80|fc|fd)/i;

async function lookupGeo(ip) {
  if (!ip || ip === "Not provided") return null;

  if (ip === "127.0.0.1" || ip === "localhost") {
    return "Localhost (This PC)";
  }

  if (privateIpPattern.test(ip)) {
    return "Local Network (Wi-Fi)";
  }

  if (process.env.GEO_LOOKUP === "0") {
    return null;
  }

  if (geoCache.has(ip)) {
    return geoCache.get(ip);
  }

  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}?fields=success,city,region,country`, {
      signal: AbortSignal.timeout(2000)
    });
    const data = await res.json();
    if (data && data.success) {
      const parts = [data.city, data.region, data.country].filter(Boolean);
      const loc = parts.length ? parts.join(", ") : null;
      geoCache.set(ip, loc);
      return loc;
    }
  } catch {
    // Geo lookup timed out or failed gracefully
  }

  geoCache.set(ip, null);
  return null;
}

// ==========================================
// 5. TRAFFIC SOURCE & AGENT CLASSIFIER
// ==========================================
function parseSource(ref, referrer) {
  if (ref && String(ref).trim()) {
    const cleanRef = String(ref).trim().slice(0, 50);
    if (/^linkedin/i.test(cleanRef)) return "LinkedIn";
    if (/^whatsapp/i.test(cleanRef)) return "WhatsApp";
    if (/^resume/i.test(cleanRef)) return "Resume Link";
    if (/^github/i.test(cleanRef)) return "GitHub";
    if (/^instagram/i.test(cleanRef)) return "Instagram";
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

const BOT_PATTERN = /bot|crawl|spider|slurp|facebookexternalhit|headless|monitor|uptime|pingdom|lighthouse|curl\/|wget|python-requests|axios|node-fetch|go-http-client|okhttp/i;

// In-memory rate limiters
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

// ==========================================
// 6. READ & WRITE VISITOR LOGS
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
          const isOwner = Boolean(item.isOwner || (item.name && item.name.includes("Owner")));
          return {
            time: item.time,
            ip: cleanIp(item.ip),
            page: item.page || "/",
            userAgent: item.userAgent,
            device: item.device || agentInfo.os + " (" + agentInfo.deviceType + ")",
            browser: item.browser || agentInfo.browser,
            source: source,
            referrer: item.referrer || null,
            location: loc,
            vid: item.vid || item.ip,
            name: item.name || (item.ref && item.ref.startsWith("Introduced:") ? item.ref.replace(/^Introduced:\s*/, "") : null),
            isOwner: isOwner
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
        `SELECT time, ip, page, user_agent AS "userAgent", source, referrer, device, browser, location, vid, name, COALESCE(is_owner, false) AS "isOwner"
         FROM portfolio_visits
         ORDER BY time DESC
         LIMIT 500`
      );
      if (res.rows.length > 0) {
        return res.rows.map(r => ({
          ...r,
          ip: cleanIp(r.ip),
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
  // 1. Write to local visits.jsonl file
  try {
    fs.appendFileSync(logPath, JSON.stringify(entry) + "\n", "utf8");
  } catch (err) {
    console.error("Local file write error:", err.message);
  }

  // 2. Persist to PostgreSQL if connected
  if (dbPool) {
    try {
      await dbPool.query(
        `INSERT INTO portfolio_visits (time, ip, page, user_agent, source, referrer, device, browser, location, vid, name, is_owner)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
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
          entry.name,
          Boolean(entry.isOwner)
        ]
      );
    } catch (err) {
      console.error("Database insert error:", err.message);
    }
  }
}

// ==========================================
// 7. HTML RENDERING: LOGIN PAGE
// ==========================================
function renderLoginPage(errorMessage = "", successMessage = "") {
  const currentUsername = escapeHtml(getOwnerUsername());
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sign In | Portfolio Owner Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Source+Sans+3:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #070b16;
  --card: #0f172a;
  --border: #263556;
  --primary: #8b5cf6;
  --primary-hover: #7c3aed;
  --cyan: #06b6d4;
  --lime: #a3e635;
  --crimson: #ef4444;
  --text: #f8fafc;
  --muted: #94a3b8;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: radial-gradient(ellipse at 20% 20%, #1e1548 0, transparent 45%),
              radial-gradient(ellipse at 80% 80%, #06313f 0, transparent 40%),
              var(--bg);
  color: var(--text);
  font: 15px/1.6 'Source Sans 3', system-ui, sans-serif;
  padding: 20px;
}
.login-card {
  width: 100%;
  max-width: 420px;
  background: rgba(15, 23, 42, 0.92);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 36px 30px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.65), 0 0 40px rgba(139, 92, 246, 0.15);
  position: relative;
  overflow: hidden;
}
.login-card::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0; height: 3px;
  background: linear-gradient(90deg, var(--primary), var(--cyan), var(--lime));
}
.brand-badge {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: var(--cyan);
  background: rgba(6, 182, 212, 0.12);
  border: 1px solid rgba(6, 182, 212, 0.25);
  padding: 4px 10px;
  border-radius: 999px;
  margin-bottom: 14px;
}
.pulse-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--cyan);
  box-shadow: 0 0 8px var(--cyan);
}
h1 {
  font-family: 'Outfit', sans-serif;
  font-size: 1.8rem;
  margin: 0 0 6px;
  font-weight: 750;
  letter-spacing: -0.02em;
}
p.sub {
  color: var(--muted);
  font-size: 13.5px;
  margin: 0 0 24px;
}
.alert {
  padding: 12px 14px;
  border-radius: 10px;
  font-size: 13.5px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.alert-error {
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.35);
  color: #fca5a5;
}
.alert-success {
  background: rgba(163, 230, 53, 0.15);
  border: 1px solid rgba(163, 230, 53, 0.35);
  color: #bef264;
}
.form-group {
  margin-bottom: 18px;
}
label {
  display: block;
  font-size: 12.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #cbd5e1;
  margin-bottom: 7px;
}
.input-wrap {
  position: relative;
  display: flex;
  align-items: center;
}
input[type="text"], input[type="password"] {
  width: 100%;
  background: #090e1c;
  border: 1px solid var(--border);
  color: #fff;
  padding: 11px 14px;
  border-radius: 10px;
  font-size: 14px;
  font-family: inherit;
  transition: border-color .2s, box-shadow .2s;
}
input[type="text"]:focus, input[type="password"]:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.25);
}
.toggle-btn {
  position: absolute;
  right: 10px;
  background: transparent;
  border: none;
  color: var(--muted);
  cursor: pointer;
  padding: 6px;
  font-size: 14px;
}
.toggle-btn:hover { color: #fff; }
.btn-submit {
  width: 100%;
  padding: 12px;
  margin-top: 8px;
  background: linear-gradient(135deg, var(--primary), #6d28d9);
  color: #fff;
  border: none;
  border-radius: 10px;
  font-family: 'Outfit', sans-serif;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  box-shadow: 0 4px 15px rgba(139, 92, 246, 0.35);
  transition: transform .15s, box-shadow .15s;
}
.btn-submit:hover {
  background: linear-gradient(135deg, var(--primary-hover), #5b21b6);
  transform: translateY(-1px);
  box-shadow: 0 6px 20px rgba(139, 92, 246, 0.45);
}
.btn-submit:active { transform: translateY(1px); }
.help-box {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid var(--border);
  font-size: 12.5px;
  color: var(--muted);
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.back-link {
  color: #93c5fd;
  text-decoration: none;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.back-link:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="login-card">
  <div class="brand-badge"><span class="pulse-dot"></span> OWNER PORTAL</div>
  <h1>Protected Sign In</h1>
  <p class="sub">Enter your credentials to access live visitor tracking & analytics.</p>

  ${errorMessage ? `<div class="alert alert-error">⚠️ ${escapeHtml(errorMessage)}</div>` : ""}
  ${successMessage ? `<div class="alert alert-success">✅ ${escapeHtml(successMessage)}</div>` : ""}

  <form method="POST" action="/owner/login">
    <div class="form-group">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="e.g. admin" required autofocus autocomplete="username" value="${currentUsername}">
    </div>

    <div class="form-group">
      <label for="password">Password</label>
      <div class="input-wrap">
        <input type="password" id="password" name="password" placeholder="Enter password" required autocomplete="current-password">
        <button type="button" class="toggle-btn" id="toggle-pw" title="Show/Hide Password">👁️</button>
      </div>
    </div>

    <button type="submit" class="btn-submit">Sign In to Dashboard →</button>
  </form>

  <div class="help-box">
    <span>🔒 Protected with credentials configured in your <code>.env</code> file (<code>OWNER_USERNAME</code> and <code>OWNER_PASSWORD</code>).</span>
    <a href="/" class="back-link">← Return to Public Portfolio</a>
  </div>
</div>

<script>
document.getElementById("toggle-pw").addEventListener("click", function() {
  var pw = document.getElementById("password");
  if (pw.type === "password") {
    pw.type = "text";
    this.textContent = "🙈";
  } else {
    pw.type = "password";
    this.textContent = "👁️";
  }
});
</script>
</body>
</html>`;
}

// ==========================================
// 8. HTML RENDERING: OWNER DASHBOARD
// ==========================================
function renderDashboardPage(visits, req) {
  const totalVisits = visits.length;
  const visitorVisits = visits.filter(v => !v.isOwner);
  const ownerVisits = visits.filter(v => v.isOwner);
  const uniqueVisitors = new Set(visitorVisits.map(v => v.vid || v.ip)).size;
  const last24h = visits.filter(v => Date.now() - Date.parse(v.time) < 24 * 60 * 60 * 1000).length;

  const sourceCounts = {};
  for (const v of visits) {
    const src = v.source || "Direct / Message";
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  }

  const sortedSources = Object.entries(sourceCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  const sourceBadgesHtml = sortedSources.map(([src, count]) => {
    const percent = totalVisits > 0 ? Math.round((count / totalVisits) * 100) : 0;
    let icon = "🔗";
    if (src.includes("LinkedIn")) icon = "💼";
    else if (src.includes("WhatsApp")) icon = "💬";
    else if (src.includes("Google")) icon = "🔍";
    else if (src.includes("Instagram")) icon = "📸";
    else if (src.includes("GitHub")) icon = "🐙";
    else if (src.includes("Resume")) icon = "📄";
    else if (src.includes("Owner")) icon = "👑";
    return `<span class="source-pill">${icon} <b>${escapeHtml(src)}</b> <small>${count} (${percent}%)</small></span>`;
  }).join("") || `<span style="color:var(--muted)">No traffic sources recorded yet.</span>`;

  const rowsHtml = visits.map(v => {
    let displayName = "🌐 Anonymous Visitor";
    let nameClass = "";

    if (v.isOwner) {
      displayName = `👑 You (Owner Test)`;
      nameClass = "is-owner";
    } else if (v.name) {
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
    else if (src.includes("Owner")) sourceIcon = "👑";

    let locHtml = "—";
    if (v.location) {
      if (v.location.includes("Localhost")) locHtml = `💻 ${escapeHtml(v.location)}`;
      else if (v.location.includes("Wi-Fi")) locHtml = `📶 ${escapeHtml(v.location)}`;
      else locHtml = `📍 ${escapeHtml(v.location)}`;
    }

    const dev = escapeHtml(v.device || "Desktop");
    const browser = escapeHtml(v.browser || "Browser");
    const ipClean = escapeHtml(v.ip || "Not provided");
    const rowFilterType = v.isOwner ? "owner" : "visitor";

    return `
    <tr data-type="${rowFilterType}">
      <td class="${nameClass}"><strong>${displayName}</strong></td>
      <td><time datetime="${escapeHtml(v.time)}">${escapeHtml(v.time)}</time></td>
      <td><span class="source-tag">${sourceIcon} ${escapeHtml(src)}</span></td>
      <td>${locHtml}</td>
      <td>${dev} · ${browser}</td>
      <td><code>${escapeHtml(v.page)}</code></td>
      <td>
        <span class="ip-badge-wrap">
          <code class="ip-code">${ipClean}</code>
          <button class="copy-btn" onclick="copyIp(this, '${ipClean}')" title="Copy IP address">📋</button>
        </span>
      </td>
    </tr>
    `;
  }).join("");

  const storageStatus = dbPool ? "Cloud Database (PostgreSQL)" : "Local Storage (visits.jsonl)";
  const username = escapeHtml(getOwnerUsername());

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Visitor Intelligence | Owner Dashboard</title>
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
  --gold:#f59e0b;
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
main{max-width:1200px;width:92%;margin:40px auto 60px}
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
.header-actions{display:flex;align-items:center;flex-wrap:wrap;gap:10px}
.btn{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:8px 14px;
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
.btn-danger{background:#45121b;color:#fca5a5;border-color:#7f1d1d}
.btn-danger:hover{background:#7f1d1d;color:#fff}

.stats-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
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
.stat-card small{color:var(--cyan);font-size:11.5px;font-weight:600}

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
  gap:14px;
  margin-bottom:14px;
}
.filter-tabs{display:flex;gap:8px}
.tab-btn{
  background:#131c36;
  border:1px solid var(--border);
  color:var(--muted);
  padding:6px 14px;
  border-radius:20px;
  font-size:12.5px;
  font-weight:600;
  cursor:pointer;
  transition:.15s;
}
.tab-btn.active{
  background:var(--primary);
  border-color:var(--primary);
  color:#fff;
}
.search-box{
  background:#0e162b;
  border:1px solid var(--border);
  color:#fff;
  padding:9px 14px;
  border-radius:8px;
  font-size:13px;
  width:290px;
}
.search-box:focus{outline:none;border-color:var(--primary)}

.table-wrap{
  overflow-x:auto;
  border:1px solid var(--border);
  border-radius:14px;
  background:#0d1427;
}
table{border-collapse:collapse;width:100%;min-width:920px}
th,td{text-align:left;padding:13px 16px;border-bottom:1px solid #1e293b}
th{color:#93c5fd;background:#111a30;font-size:12px;letter-spacing:.05em;text-transform:uppercase;font-weight:700}
td{font-size:13.5px}
tbody tr:hover{background:#131c3566}

.is-owner strong{color:var(--gold)}
.is-introduced strong{color:var(--lime)}
.source-tag{
  background:#1e293b;
  padding:3px 8px;
  border-radius:6px;
  font-size:12px;
  font-weight:600;
  border:1px solid #334155;
}
code{background:#1e293b;color:#a5b4fc;padding:2px 6px;border-radius:4px;font-size:12px}
.ip-badge-wrap{display:inline-flex;align-items:center;gap:6px}
.ip-code{color:#cbd5e1;font-weight:600}
.copy-btn{
  background:transparent;
  border:none;
  cursor:pointer;
  font-size:13px;
  padding:2px 4px;
  border-radius:4px;
  transition:.15s;
}
.copy-btn:hover{background:#334155}

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
        <span class="badge-live"><span class="pulse"></span> LIVE INTELLIGENCE</span>
        <span style="font-size:12px;color:var(--muted);font-weight:600">SIGNED IN AS: <b style="color:#fff">${username}</b></span>
      </div>
      <h1>Visitor Traffic & IP Intelligence</h1>
    </div>
    <div class="header-actions">
      <a href="/owner/export.csv" class="btn" title="Download all visit logs as CSV">📥 Export CSV</a>
      <button onclick="clearLogs()" class="btn btn-danger" title="Clear visit records">🗑️ Clear Logs</button>
      <a href="/owner/logout" class="btn">🚪 Sign Out</a>
      <a href="/" class="btn btn-primary">← View Portfolio</a>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <b>${totalVisits}</b>
      <span>TOTAL VISITS RECORDED</span>
      <small>${visitorVisits.length} visitors · ${ownerVisits.length} owner tests</small>
    </div>
    <div class="stat-card">
      <b>${uniqueVisitors}</b>
      <span>UNIQUE VISITORS</span>
      <small>Distinct IP & visitor IDs</small>
    </div>
    <div class="stat-card">
      <b>${last24h}</b>
      <span>ACTIVE LAST 24 HOURS</span>
      <small>Recent visitor impressions</small>
    </div>
    <div class="stat-card">
      <b>${sortedSources[0] ? escapeHtml(sortedSources[0][0]) : "Direct"}</b>
      <span>TOP TRAFFIC SOURCE</span>
      <small>${sortedSources[0] ? sortedSources[0][1] + " visits" : "No visits"}</small>
    </div>
  </div>

  <div class="breakdown-section">
    <div class="breakdown-title">Top Traffic Sources & Referrals</div>
    <div class="sources-list">
      ${sourceBadgesHtml}
    </div>
  </div>

  <div class="table-header-row">
    <div class="filter-tabs">
      <button class="tab-btn active" data-filter="all" onclick="setTab('all')">All Visits (${totalVisits})</button>
      <button class="tab-btn" data-filter="visitor" onclick="setTab('visitor')">Visitors Only (${visitorVisits.length})</button>
      <button class="tab-btn" data-filter="owner" onclick="setTab('owner')">Owner Tests (${ownerVisits.length})</button>
    </div>
    <input type="text" id="filter-input" class="search-box" placeholder="Filter by IP, name, source, location, browser...">
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
          <th>Visitor IP Address</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml || '<tr><td colspan="7" style="text-align:center;padding:35px;color:var(--muted)">No visits recorded yet. Share your portfolio link to start tracking!</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="footer-info">
    <div class="status-pill">
      <span>💾 Storage Backend:</span> <b>${storageStatus}</b>
    </div>
    <div>
      Real client IP detection active. Proxy headers automatically verified for accurate geolocation.
    </div>
  </div>
</main>

<script>
// Format timestamps to local viewer time
document.querySelectorAll("time[datetime]").forEach(function(el) {
  var d = new Date(el.getAttribute("datetime"));
  if (!isNaN(d)) el.textContent = d.toLocaleString();
});

// Copy IP Address helper
function copyIp(btn, ip) {
  navigator.clipboard.writeText(ip).then(function() {
    var original = btn.textContent;
    btn.textContent = "✓";
    setTimeout(function() { btn.textContent = original; }, 1500);
  });
}

// Clear visitor logs
function clearLogs() {
  if (!confirm("Are you sure you want to permanently clear all visitor logs?")) return;
  fetch("/owner/clear-logs", { method: "POST" })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.success) {
        window.location.reload();
      } else {
        alert("Failed to clear logs: " + (data.error || "Unknown error"));
      }
    })
    .catch(function(err) {
      alert("Error: " + err.message);
    });
}

// Table filtering by tab and search
var currentTab = "all";
function setTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab-btn").forEach(function(btn) {
    btn.classList.toggle("active", btn.getAttribute("data-filter") === tab);
  });
  applyFilters();
}

function applyFilters() {
  var query = (document.getElementById("filter-input")?.value || "").toLowerCase().trim();
  document.querySelectorAll("#visitors-table tbody tr[data-type]").forEach(function(row) {
    var rowType = row.getAttribute("data-type");
    var tabMatch = (currentTab === "all") || (currentTab === rowType);
    var textMatch = !query || row.textContent.toLowerCase().indexOf(query) !== -1;
    row.style.display = (tabMatch && textMatch) ? "" : "none";
  });
}

var searchInput = document.getElementById("filter-input");
if (searchInput) {
  searchInput.addEventListener("input", applyFilters);
}
</script>
</body>
</html>`;
}

// ==========================================
// 9. HTTP SERVER ROUTING
// ==========================================
const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, "http://localhost");
  } catch {
    return send(res, 400, "text/plain; charset=utf-8", "Bad request");
  }

  // ------------------------------------------
  // A. OWNER DASHBOARD ROUTE: /owner
  // ------------------------------------------
  if (url.pathname === "/owner") {
    if (req.method !== "GET") {
      return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
    }

    if (!isOwnerAuthorized(req)) {
      const loggedOut = url.searchParams.get("logged_out") === "1";
      const successMsg = loggedOut ? "You have been successfully signed out." : "";
      return send(res, 200, "text/html; charset=utf-8", renderLoginPage("", successMsg));
    }

    const visits = await getAllVisits();
    return send(res, 200, "text/html; charset=utf-8", renderDashboardPage(visits, req));
  }

  // ------------------------------------------
  // B. OWNER LOGIN ROUTES: /owner/login
  // ------------------------------------------
  if (url.pathname === "/owner/login") {
    if (req.method === "GET") {
      if (isOwnerAuthorized(req)) {
        res.writeHead(302, { "Location": "/owner" });
        return res.end();
      }
      return send(res, 200, "text/html; charset=utf-8", renderLoginPage());
    }

    if (req.method === "POST") {
      const clientIp = getClientIp(req);
      const blocked = (authFails.get(clientIp)?.count || 0) >= 5 &&
        Date.now() - authFails.get(clientIp).start < 15 * 60 * 1000;

      if (blocked) {
        return send(res, 429, "text/html; charset=utf-8",
          renderLoginPage("Too many failed login attempts. Please wait 15 minutes before trying again."));
      }

      let bodyData = "";
      req.on("data", chunk => {
        bodyData += chunk;
        if (bodyData.length > 50000) req.destroy();
      });

      req.on("end", () => {
        let username = "";
        let password = "";

        const contentType = req.headers["content-type"] || "";
        if (contentType.includes("application/json")) {
          try {
            const parsed = JSON.parse(bodyData || "{}");
            username = String(parsed.username || "").trim();
            password = String(parsed.password || "");
          } catch {}
        } else {
          const params = new URLSearchParams(bodyData);
          username = String(params.get("username") || "").trim();
          password = String(params.get("password") || "");
        }

        const userMatch = safeCompare(username, getOwnerUsername());
        const passMatch = safeCompare(password, getOwnerPassword());

        if (userMatch && passMatch) {
          authFails.delete(clientIp);
          const headers = {
            "Location": "/owner",
            "Set-Cookie": sessionCookieHeaders(req)
          };
          res.writeHead(302, headers);
          return res.end();
        }

        rateLimited(authFails, clientIp, 5, 15 * 60 * 1000);
        return send(res, 401, "text/html; charset=utf-8",
          renderLoginPage("Invalid username or password. Please verify your credentials in .env."));
      });
      return;
    }

    return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
  }

  // ------------------------------------------
  // C. OWNER LOGOUT ROUTE: /owner/logout
  // ------------------------------------------
  if (url.pathname === "/owner/logout") {
    res.writeHead(302, {
      "Location": "/owner?logged_out=1",
      "Set-Cookie": clearCookieHeaders(req)
    });
    return res.end();
  }

  // ------------------------------------------
  // D. OWNER CLEAR LOGS ROUTE: /owner/clear-logs
  // ------------------------------------------
  if (url.pathname === "/owner/clear-logs") {
    if (req.method !== "POST") {
      return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
    }

    if (!isOwnerAuthorized(req)) {
      return send(res, 401, "application/json; charset=utf-8", JSON.stringify({ error: "Unauthorized" }));
    }

    try {
      fs.writeFileSync(logPath, "", "utf8");
      if (dbPool) {
        await dbPool.query("TRUNCATE TABLE portfolio_visits;");
      }
      return send(res, 200, "application/json; charset=utf-8", JSON.stringify({ success: true }));
    } catch (err) {
      return send(res, 500, "application/json; charset=utf-8", JSON.stringify({ error: err.message }));
    }
  }

  // ------------------------------------------
  // E. EXPORT VISITOR DATA TO CSV: /owner/export.csv
  // ------------------------------------------
  if (url.pathname === "/owner/export.csv") {
    if (req.method !== "GET") {
      return send(res, 405, "text/plain; charset=utf-8", "Method not allowed");
    }

    if (!isOwnerAuthorized(req)) {
      res.writeHead(302, { "Location": "/owner" });
      return res.end();
    }

    const visits = await getAllVisits();
    const csvHeader = "Time,Visitor Name,Status,Traffic Source,Location,Device,Browser,Page,IP Address,Referrer URL\r\n";
    const escapeCsv = v => `"${String(v ?? "").replace(/"/g, '""')}"`;

    const csvRows = visits.map(v => [
      escapeCsv(v.time),
      escapeCsv(v.name || "Anonymous"),
      escapeCsv(v.isOwner ? "Owner Test" : "Public Visitor"),
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
  // F. RECORD VISIT: /api/visit
  // ------------------------------------------
  if (url.pathname === "/api/visit") {
    const json = (status, body) =>
      send(res, status, "application/json; charset=utf-8", JSON.stringify(body));

    const userAgent = String(req.headers["user-agent"] || "Not provided").slice(0, 300);
    if (BOT_PATTERN.test(userAgent)) return json(200, { recorded: false, reason: "bot" });

    const ip = getClientIp(req);
    const isOwner = isSessionValid(req);

    // Rate-limit external visitors (allow up to 30 requests/min), don't block owner testing
    if (!isOwner && rateLimited(visitHits, ip, 30, 60 * 1000)) {
      return json(429, { recorded: false, reason: "rate-limited" });
    }

    const processPayload = async (pagePath, referrer, refParam, vid) => {
      if (!pagePath || !pagePath.startsWith("/") || pagePath.length > 200) pagePath = "/";

      const agentInfo = describeAgent(userAgent);
      const source = isOwner ? "Owner (Self Test)" : parseSource(refParam, referrer);
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
        name: isOwner ? "👑 Owner (You - Test Visit)" : null,
        isOwner: isOwner
      };

      await recordVisitEntry(entry);
      return json(200, { recorded: true, ip: ip, isOwner: isOwner });
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
  // G. SELF-IDENTIFY VISIT: /api/visit/identify
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
          name: rawName,
          isOwner: false
        };

        await recordVisitEntry(entry);
        return json(200, { success: true, recorded: true });
      } catch {
        return json(400, { success: false, error: "Invalid JSON" });
      }
    });
    return;
  }

  // ------------------------------------------
  // H. PUBLIC PORTFOLIO STATIC FILE SERVING
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
// 10. PORT LISTENER
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

  server.listen(port, "0.0.0.0", () => {
    const address = server.address();
    console.log(`Portfolio running at http://localhost:${address.port}`);
    console.log(`Protected owner dashboard available at http://localhost:${address.port}/owner`);
    console.log(`Owner username: ${getOwnerUsername()}`);
  });
}

listenOnPort(targetPort);
