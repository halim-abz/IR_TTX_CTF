# Incident Guild CTF — Multiplayer Tournament (Version 5 rules)

A hosted, multiplayer capture-the-flag-style incident response exercise **based on Incident Guild Version 5**, using the original three scenario definitions, NetWitness Logs / Network / Endpoint simulated evidence, D20 decisions, investigation queries, conclusions, and grading logic.

Players compete **independently** in the same tournament. No account registration or passwords for players: each player claims an available username once and gets a private browser session cookie. The server holds game state and calculates scores; browsers cannot submit their own final score.

## Quick start (Node.js 22+; no npm install needed)

Download and unzip this project, open a terminal in its folder, and start the server:

**macOS / Linux**

```bash
export ADMIN_PASSWORD='choose-a-strong-private-password'
export HOST=0.0.0.0
export PORT=3000
node server/server.cjs
```

**Windows PowerShell**

```powershell
$env:ADMIN_PASSWORD = Read-Host "Choose a strong private admin password"
$env:HOST = '0.0.0.0'
$env:PORT = '3000'
node .\server\server.cjs
```

Visit `http://localhost:3000` on the host. Share `http://YOUR-SERVER-LAN-IP:3000` with players on the same reachable LAN. All players must use the **same running server** to share rankings; opening HTML as a local file cannot do that. Permit TCP 3000 through a firewall if needed. To serve users over the internet, deploy behind **HTTPS**, set `COOKIE_SECURE=1`, and configure a reverse proxy that supports server-sent events and forwards the correct `Host` header. **Do not expose the plain HTTP setup to the internet.**

You can run with Docker Compose instead:

```bash
cp .env.example .env
# Edit .env and replace ADMIN_PASSWORD with a strong secret.
docker compose up -d --build
```

Then visit `http://localhost:3000`, or your HTTPS domain if configured.

## How the competition works

1. Each player picks a unique username (3–24 characters, letters/digits/underscores/hyphens).
2. The server issues a browser-bound session token. The token is stored as an HttpOnly cookie. Players can close the page and resume from that browser while their token remains valid. The prototype has **no lost-session or username recovery**. A different browser cannot reclaim an existing username without the original token.
3. Everyone completes exactly one attempt at each of the three v5 scenarios, in this order: **The Midnight Ticket**, **Paper Lantern**, and **The Valve Room**. A failed or catastrophic scenario also counts as a completed attempt. The next scenario unlocks only when the active one ends.
4. Investigate with simulated NetWitness Logs / Network / Endpoint datasets; collect findings, submit evidence-backed conclusions, and use vendor-neutral external response controls for containment and remediation.
5. The server reuses the original v5 scoring rules. Each incident is scored out of 100, so final maximum is **300 points**. It displays **finalized points plus clearly labeled provisional points** while a scenario is active. Live ranks change after every move via server-sent events; once an incident ends, its final score is locked.
6. On completion, players can review score breakdowns, objectives, and the incident chronicle. They cannot replay a finished scenario unless the entire tournament is reset by an administrator.

**Tournament fairness:** All competitors use **Standard** dice difficulty, the same fixed per-scenario pseudorandom roll sequence for the current competition epoch, the same v5 incident evidence and scoring, and a single permitted attempt per stage. Different action orders may consume random draws differently. This is suitable for facilitated training competitions, not a fraud-proof public prize tournament without stronger player identity checks, limits, and anti-abuse controls.

## Admin reset

Select **Admin tools**, enter the administrator password, and type `RESET EVERYTHING` to confirm. This clears **all player usernames, session tokens, incident histories, completed scores, and leaderboard entries**, and starts a fresh tournament with new random dice seeds. Existing clients are notified automatically and must choose a username again. Old cookies cease to authorize access.

The admin password comes from `ADMIN_PASSWORD`. If the environment variable is not supplied, a random password is generated and printed in the server's terminal **at startup**. For operational use, supply a secret explicitly instead of depending on terminal output. Admin reset attempts are rate limited. A forgotten password can be changed by restarting the server with a new `ADMIN_PASSWORD` (without deleting the competition database).

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
server/core/         Original Incident Guild v5 engine, data and telemetry (not public)
tests/               API, full-tournament and browser test scripts
Dockerfile           Optional container deployment
docker-compose.yml   Persistent Docker deployment
```

## Testing

- Node.js: `node --check server/server.cjs` and `node --check public/app.js`.
- Integration tests were exercised against a running server: multi-player signup, duplicate usernames, session continuity, server-side resolution, restrictions on stages, score aggregation across all three scenarios, lost permissions after admin reset, and browser rendering at desktop and mobile widths.
- The included `tests/` scripts are developer smoke tests and expect a **locally running server** at port 8844; configure their base URLs before running. They use `requests` and (for browser tests) Python Playwright. No Python dependency is required for the application itself.

## Investigation workbench enhancements (this update)

The multiplayer build remains **strictly based on the Version 5 Incident Guild scenarios and scoring engine**. New detail is confined to the fictional investigation records and player interface. The shared server, one-attempt-per-scenario rules, real-time leaderboard and password-protected tournament reset work the same way.

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
