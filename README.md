# Incident Trace CTF — Multiplayer Tournament (Version 5 rules)

A hosted, multiplayer capture-the-flag-style incident response exercise with a streamlined four-workspace UI **based on the original Incident Guild Version 5 engine**, using the three original Version 5 scenarios plus a new webshell challenge, NetWitness Logs / Network / Endpoint simulated evidence, D20 decisions, investigation queries, conclusions, and grading logic.

Players compete **independently** in the same tournament. No account registration or passwords for players: each player claims an available username once and gets a private browser session cookie. The server holds game state and calculates scores; browsers cannot submit their own final score.

## Quick start (Node.js 22+; no npm install needed)

Download and unzip this project, open a terminal in its folder, and start the server:

**macOS / Linux**

```bash
# Optional: export ADMIN_PASSWORD='a-long-private-password' (otherwise one is generated and saved)
export HOST=0.0.0.0
export PORT=3000
node server/server.cjs
```

**Windows PowerShell**

```powershell
$env:ADMIN_PASSWORD = Read-Host "Optional private admin password (leave blank to generate)"
$env:HOST = '0.0.0.0'
$env:PORT = '3000'
node .\server\server.cjs
```

Visit `http://localhost:3000` on the host. Share `http://YOUR-SERVER-LAN-IP:3000` with players on the same reachable LAN. All players must use the **same running server** to share rankings; opening HTML as a local file cannot do that. Permit TCP 3000 through a firewall if needed. To serve users over the internet, deploy behind **HTTPS**, set `COOKIE_SECURE=1`, and configure a reverse proxy that supports server-sent events and forwards the correct `Host` header. **Do not expose the plain HTTP setup to the internet.**

You can run with Docker Compose instead:

```bash
cp .env.example .env
# Leave ADMIN_PASSWORD empty to auto-generate a unique password.
# Set HOST_PORT=3030 (already the Docker default).
# COOKIE_SECURE=1 when accessing from Cloudflare HTTPS.
docker compose up -d --build
# Read the generated admin password:
docker compose logs | grep "administrator password"
```

Then visit `http://localhost:3030`, or your Cloudflare HTTPS domain if configured. The application still listens on port 3000 *inside* Docker.

## How the competition works

1. Each player picks a unique username (3–24 characters, letters/digits/underscores/hyphens).
2. The server issues a browser-bound session token. The token is stored as an HttpOnly cookie. Players can close the page and resume from that browser while their token remains valid. The prototype has **no lost-session or username recovery**. A different browser cannot reclaim an existing username without the original token.
3. Everyone completes exactly one attempt at each of four scenarios, in this order: **The Midnight Ticket**, **Paper Lantern**, **The Valve Room**, and **The Hidden Handler**. A failed or catastrophic scenario also counts as a completed attempt. The next scenario unlocks only when the active one ends.
4. Investigate with simulated NetWitness Logs / Network / Endpoint datasets; collect findings, submit evidence-backed conclusions, and use vendor-neutral external response controls for containment and remediation.
5. The server uses the Version 5 scoring model, with seven points reallocated to evidence-derived CTF flags. Each incident is scored out of 100, including up to 7 points for two forensic flags, so the four-stage maximum is **400 points**. It displays **finalized points plus clearly labeled provisional points** while a scenario is active. Live ranks change after every move via server-sent events; once an incident ends, its final score is locked.
6. On completion, players can review score breakdowns, objectives, and the incident chronicle. They cannot replay a finished scenario unless the entire tournament is reset by an administrator.

**Tournament fairness:** All competitors use **Standard** dice difficulty, the same fixed per-scenario pseudorandom roll sequence for the current competition epoch, the same v5 incident evidence and scoring, and a single permitted attempt per stage. Different action orders may consume random draws differently. This is suitable for facilitated training competitions, not a fraud-proof public prize tournament without stronger player identity checks, limits, and anti-abuse controls.

## Admin reset

Select **Admin tools**, enter the administrator password, and type `RESET EVERYTHING` to confirm. This clears **all player usernames, session tokens, incident histories, completed scores, and leaderboard entries**, and starts a fresh tournament with new random dice seeds. Existing clients are notified automatically and must choose a username again. Old cookies cease to authorize access.

The admin password comes from `ADMIN_PASSWORD`, if configured. Otherwise, a **unique 32-character password is generated on first startup**, stored persistently in `data/admin-password.txt` (inside Docker at `/app/data/admin-password.txt`), and displayed in the server logs on every start. It does not change after a restart or image rebuild. For operational use, supply a secret explicitly instead of depending on terminal output. Admin reset attempts are rate limited. To retrieve the generated password on Docker: `docker compose exec -T incident-guild-ctf cat /app/data/admin-password.txt`. To replace it, configure a unique `ADMIN_PASSWORD` in `.env` and recreate the container. Never publish a fixed default password or commit `.env`/`data/` to GitHub.

## Data and operating constraints

- Persistent tournament records are saved atomically in `data/competition.json` (or `DATA_DIR/competition.json`). Back up this directory if results are important. Never put it in a public web directory or distribute it with scores or session hashes.
- Uses a single Node.js process and synchronous in-process file writes. Do **not** run multiple instances sharing the same data file; use a transactional database / centralized session store to scale beyond this prototype.
- Default player cap: 250 usernames per tournament. Per-session move rate is limited. All request mutations require the same origin, and reset requires a separate administrator password.
- The server validates every search, evidence collection, decision, role and incident transition using the **v5 game engine** in an isolated JavaScript runtime. It does **not** accept browser-calculated scores or game state.
- This system is a game, not a live NetWitness integration. Fields and forensic records are fictional. Enforcing firewall blocks, quarantines, token revocations, backups, or OT plant changes belongs to separate vendor-neutral tools.
- Username-only play does not prove identity. A user can create multiple usernames from different browsers, and there is no way to recover a lost cookie in this first release. For formal competitions or prizes, add identity verification, team administration and stronger anti-cheating controls.

## Folder structure

```
public/              CTF frontend (responsive interface, live scoreboard, admin page)
server/server.cjs    Node HTTP/SSE server, sessions, API, tournament persistence, admin reset
server/simulator.cjs  Server-authoritative adapter for the Version 5 game engine
server/core/         Original original Version 5 engine, data and telemetry (not public)
tests/               API, full-tournament and browser test scripts
Dockerfile           Optional container deployment
docker-compose.yml   Persistent Docker deployment
```

## Testing

- Node.js: `node --check server/server.cjs` and `node --check public/app.js`.
- Integration tests were exercised against a running server: multi-player signup, duplicate usernames, session continuity, server-side resolution, restrictions on stages, score aggregation across all four scenarios, lost permissions after admin reset, and browser rendering at desktop and mobile widths.
- The included `tests/` scripts are developer smoke tests and expect a **locally running server** at port 8844; configure their base URLs before running. They use `requests` and (for browser tests) Python Playwright. No Python dependency is required for the application itself.

## Investigation workbench enhancements (this update)

The multiplayer build remains **strictly based on the Version 5 original V5 scenarios and scoring engine**. All scores and flag checks are server-authoritative. The game now uses fixed response proficiency rather than selectable specialists. The shared server, one-attempt-per-scenario rules, live leaderboard and password-protected tournament reset remain in place.

### Pivot Ideas now fill the filter

Under **NetWitness investigation**, select Logs, Network or Endpoint. The **Pivot Ideas** shown for that source are clickable; selecting one places its expression in the search box without running it or consuming incident time. Review or edit it, then click **Search (+2m)**. Each scenario has distinct example pivots; switching sources updates the list. The suggestions use this game's simplified searchable subset, not universal NetWitness parser syntax.

### Network raw bytes, decodes, and visibility limits

All simulated Network records include **sampled packet bytes** with a hexadecimal/ASCII dump and relevant protocol decodes. Expand **Packet bytes** in the result table or click **Inspect** for a larger view. The fixtures include SMB2 commands, HTTP/WinRM request headers, TLS records, RDP negotiation, and Modbus/TCP reads and write-like requests. These are fabricated training packet excerpts and **not production PCAPs** or entire captured sessions. Their decoding is illustrative; full pcap import/export is not supported.

**Crucial limitation:** The game does **not** decrypt encrypted TLS, RDP, or protected WinRM application bodies. You may see TLS record bytes, SNI (where available) and transfer metadata but **cannot** infer filenames, URLs, HTTP POST bodies or uploaded contents from ciphertext. Cleartext Modbus function codes represent requests, not confirmed physical plant changes. Unencrypted SMB2 request samples can show operation and path context, but encrypted SMB3 would not. Each sample states its visibility and forensic limitations.

### Endpoint full command lines

Every simulated Endpoint record now exposes the **entire recorded command line including arguments**, the parent command line, image path, process PID, parent PID, and working directory. This data is visible in search result rows and again in the Inspect dialog. The original suspicious PowerShell event uses a complete illustrative UTF-16LE Base64-encoded command rather than a `[redacted]` placeholder. Commands belong to a synthetic training environment, not a real live system.

You may search the following additional fields in the simplified query engine:

```
command.line ~ 'EncodedCommand'
process.path ~ 'powershell.exe'
process.pid = 4732
parent.command.line ~ 'wsmprovhost'
```

### Evidence guidance without revealing answers

The new **Investigation Field Guide** appears above the search box. Each scenario contains four goals indicating *what must be established*, *which evidence sources are useful* and *why they matter*. Source chips switch directly to the relevant workspace and provide a starting query. An investigation goal becomes fully marked **Correlated** only once all specified supporting exhibits have been collected; partial progress is labeled separately. Tips are equal for all competitors, optional to hide and reveal, and do not provide correct multiple-choice conclusions.

### Competition and deployment

Use the existing [Quick start](#quick-start-nodejs-22-no-npm-install-needed) instructions unchanged. This is a drop-in replacement project: deploy this package to the same **single** Node.js CTF instance and preserve the `data/` directory to keep an ongoing tournament. The new fields are derived from fixed scenario fixtures on the server, so previously saved player events can be replayed consistently. For an equitable competition, consider announcing the new inspection capabilities to every player at the same time; the administrator can reset the tournament if everyone should restart under the new rules.


## UX refresh — compact competition workspace

This build is still the **Version 5 gameplay and authoritative tournament scoring engine**. The redesign affects the client layout, not scenario content or score calculations.

- **Four navigation destinations:** Mission, Investigation, Casebook, Rankings. Admin settings are a small settings control rather than a permanent primary navigation category.
- **Mission screen:** Ready, Response, Investigate and All actions. Only available, non-hazardous tasks appear under Ready. At most six cards appear at a time; expand to see more. Completed and locked tasks stay accessible in All actions. A compact incident header has an expandable full brief.
- **Casebook:** Evidence, conclusions and after-action review appear as subtabs. Long incident chronicles are collapsed until requested.
- **Investigation:** Query input, pivot chips and record results are visible together. Results have an internal scroll region with sticky column headings. Packet reconstruction and complete endpoint command lines remain available through the Inspect dialog without expanding lengthy packet dumps in every result row.
- **Mobile:** Navigation becomes a four-cell bar. Objectives start collapsed to reduce scrolling and can be opened whenever needed. Admin settings remain accessible via the top-right gear.
- **Rankings:** Scroll inside the table for large tournaments. Server-sent events still push standings in real time.

### Ubuntu Docker Desktop and Cloudflare Tunnel

From the project directory:

```bash
# Optional: copy configuration (omit if .env already exists)
cp -n .env.example .env
# Choose COOKIE_SECURE=1 in .env once using your Cloudflare HTTPS hostname.
docker compose up -d --build
docker compose ps
docker compose logs --tail 30
```

- Docker publishes `HOST_PORT` (**3030** by default) to the application's internal port **3000**.
- If `cloudflared` is a separate Docker Desktop container, set the public hostname's HTTP origin URL to `http://host.docker.internal:3030` (assuming the two containers do not already share a custom Docker network).
- For LAN testing before enabling HTTPS-only cookies, use `COOKIE_SECURE=0`; when accessing the public HTTPS Cloudflare URL, use `COOKIE_SECURE=1` and recreate the container. The origin itself remains HTTP.
- If your earlier `.env` specifies `ADMIN_PASSWORD`, that existing secret takes precedence over the automatically generated one. To use the generated persistent default, remove or empty that setting.
- The default password is intentionally **not a globally shared demo password**. It is unique to your installation and survives restarts. Do not put an administrator password in GitHub or a publicly readable file.
- Keep your Docker volume `guild_competition_data` when upgrading. Do not run `docker compose down -v` unless you intend to destroy the tournament data.

### Local test server

For development without Docker, with Node.js 22 or newer:

```bash
HOST=127.0.0.1 PORT=3030 node server/server.cjs
```

The app runs at `http://127.0.0.1:3030` on that machine. The password will be saved to `data/admin-password.txt`. This ChatGPT environment can run local tests but cannot provide you with a durable, publicly accessible hosting address; for other devices, use your Ubuntu server / Cloudflare Tunnel.

## Version 2.0 forensic CTF release: four cases, 400 points

**Application name:** Incident Trace CTF (not Guild). The older internal Docker service and volume identifiers are intentionally preserved to protect existing Ubuntu deployments.

- Four required sequential scenarios: **The Midnight Ticket**, **Paper Lantern**, **The Valve Room**, **The Hidden Handler** (a new HTTP webshell case).
- A complete mission description and initial alert appear by default. One navigation menu is displayed at any viewport width, with an accessible mobile layout.
- **No specialist characters or lead/support staff selection.** All competitors use the same fixed investigation/response proficiency, with server-side D20 checks for operations and deterministic evidence queries.
- Logs now expose **synthetic raw event records**. Endpoint provides full command lines and parent processes. Network provides reconstructed protocol bytes and decoded fields for SMB2, cleartext HTTP/WinRM, Modbus/TCP, and HTTP obtained at a configured TLS inspection point.
- The webshell scenario includes a full HTTP request and response pair, a matching PHP worker child process, an archive command, and the receiving HTTP endpoint's upload receipt. The intended incident conclusions can be substantiated with the Logs, Network, and Endpoint datasets provided in the exercise.
- Two **server-validated CTF flags per scenario**. Players need to search and inspect the supporting record before submitting. Correct flags cost one simulated minute, incorrect guesses cost three. Both flags and two supported conclusions are required for verified closure. Seven of the original 100 scoring points are allocated to flag completion rather than increasing the per-case maximum.
- At least one flag value per scenario is derived from the **private per-tournament seed**, so it cannot simply be copied from the static GitHub source. The available log/packet/command context is modified consistently, and the resulting value is the same for everyone in one tournament. This is deterrence, not complete anti-cheat protection: determined users can still inspect public sources, and no-registration usernames cannot enforce one real person per account.

**Deployment and fair scoring:** This version changes scoring and adds a fourth mandatory stage. Existing player data is not deleted or reset automatically. Previously finalized scores from the old version are not directly comparable. **Use Admin settings → Reset everything after deploying if you are starting a fair new tournament.** Admin reset invalidates all usernames, sessions, scores, attempts, and the tournament seeds. Do not run `docker compose down -v` to reset unless you deliberately want to delete persistent Docker data.

**Cloudflare / Docker Desktop:** external port 3030 maps to internal port 3000. A tunnel running as another Docker Desktop container can typically use `http://host.docker.internal:3030` as its origin. Set `COOKIE_SECURE=1` when the public player-facing hostname uses HTTPS. The game intentionally does not have an internet-accessible server hosted by this package.

**Important technical constraints:** The records and packet bytes are a purpose-built synthetic training dataset, not real captures or universal NetWitness parser syntax. In the outbound HTTPS cases, raw TLS packets are encrypted; the exercise explicitly models an instrumented inspection point capable of providing decoded HTTP application-layer streams. WinRM cleartext commands represent a deliberately permissive fictional training environment and should never be used as a production security recommendation. Observed Modbus write acceptance must be corroborated with controller/process records before asserting physical effects; those corroborating records exist within the scenario.
