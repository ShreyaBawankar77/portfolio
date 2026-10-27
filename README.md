# Shreya Bawankar — Portfolio

A responsive, modern personal portfolio website built with plain HTML, CSS, and JavaScript, powered by a lightweight built-in Node.js server for visitor tracking and a private owner dashboard.

## How to Run

1. Open this folder in VS Code or your terminal.
2. Run:
   ```powershell
   node --env-file-if-exists=.env server.js
   ```
3. Open the printed local URL (typically **http://localhost:3000** or **http://localhost:3002** if port 3000 is occupied).

## Sharing with Friends

- **On the same Wi-Fi / Hotspot:**
  Share your local network IP (e.g. `http://192.168.1.3:3002`). Friends on the same network can open it immediately on their phones or laptops.
- **Over the Internet (Instant Free Tunnel):**
  Run in a terminal:
  ```powershell
  npx.cmd localtunnel --port 3002
  ```
  Send the generated public URL to your friends.

## Private Owner Dashboard

1. Open **`/owner`** in your browser (e.g. `http://localhost:3000/owner` or `http://localhost:3002/owner`).
2. Log in with your protected credentials:
   - **Username:** `admin` (or the username configured in `.env`).
   - **Password:** `admin` (or the password configured in `.env`).
3. View the live visitor log:
   - Real visitor IP addresses (with click-to-copy button)
   - Approximate city and country location
   - Total visits and unique visitors
   - Exact visit timestamps in your local time
   - Visitor device & browser (e.g. iPhone, Android, Chrome on Windows)
   - Visitor names (if submitted via "Say Hello")
   - Owner test visits are clearly badged (`👑 You (Owner Test)`) and can be filtered.
   - Option to export logs as CSV or clear old logs with one click.

## Configuration (.env)

Edit `.env` to customize your server port, dashboard credentials, or proxy settings:
```env
PORT=3000
OWNER_USERNAME=admin
OWNER_PASSWORD=admin
TRUST_PROXY=1
GEO_LOOKUP=1
```

## Project Structure

- `index.html` — Portfolio structure and content
- `styles.css` — Responsive design and styling
- `script.js` — Client interactions and automatic visit logging
- `server.js` — Lightweight HTTP server and private `/owner` dashboard
- `visits.jsonl` — Local visitor log storage
- `assets/` & `images/` — Photos, resume, and project assets
