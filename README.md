# The War Room: Incident Response — Multiplayer CTF v2.1

A self-hosted, educational incident response tabletop competition **based on the Incident Guild Version 5 mechanics**. Players choose a username, independently complete four NetWitness-inspired synthetic cases in sequence, investigate simulated Logs / Network / Endpoint, submit forensic CTF artifacts, and compete on a shared, live scoreboard. Scores and actions are validated on the server.

## Core gameplay

- Four compulsory scenarios: The Midnight Ticket, Paper Lantern, The Valve Room, The Hidden Handler.
- Each mission is scored from 0–100. Final total is 0–400. One attempt per scenario, in order, per username.
- Mandatory CTF flags: **both of the two source-specific flags** must be validated before the final verify action can close the scenario. They contribute **up to 7 points within the 100-point scenario score**, not 7 bonus points. Each flag requires inspection of the relevant record. Wrong flag: +3 simulated minutes; correct: +1 minute.
- Mandatory conclusions: **at least two evidence-supported conclusions** must be solved for closure. Each conclusion includes a collapsible educational hint without disclosing its answer. Wrong conclusions cost simulated time and reduce assessment points.
- Server-side D20 rolls for operational response actions, with fixed tournament difficulty and no player-specialist mechanic.
- Timed attacker events (distinct per scenario) still occur when effective countermeasures have not been deployed before their thresholds. These can degrade business availability, increase exposure, subtract score points, and impose upper score caps. **A correct action too late does not reverse the damage.**
- NetWitness is used only for *investigation*. Actual blocking, identity controls, host isolation and OT safety decisions belong to appropriate external control and operating systems.
- When a response decision is unsafe, sequenced poorly, partially effective or fails execution, the game explains the reason and recommended practice. A low D20 alone is not labeled a poor decision.
- Completed scenarios include a **learning-oriented after-action review**: overview, assessment, good and bad decisions, recommendations, attacker progression, containment timing and objective/score breakdown.

## Ubuntu / Docker Desktop (port 3030)

Use Docker Desktop's `desktop-linux` context and do not use `sudo`:

```bash
cd ~/nwttxsim/IR_TTX_CTF
docker context use desktop-linux
cp .env.example .env     # if you do not already have .env
docker compose up -d --build
docker compose ps
```

The included Compose file defaults to external port **3030** and internal container port **3000** (`HOST_PORT` can be set in `.env`). Open `http://localhost:3030` from the Ubuntu host.

If your deployment was cloned from GitHub, copy the extracted project contents into your repository, commit and push the changes, then `git pull` and `docker compose up -d --build` on Ubuntu. If you customized Compose locally, stash/merge your local differences first rather than overwriting them.

### Cloudflare Tunnel

If `cloudflared` runs as a **separate Docker Desktop container** and the app exposes host port 3030, set the tunnel origin to `http://host.docker.internal:3030` (service type `HTTP`). Alternatively place both containers on a shared user-defined network and use the Compose service name plus internal port 3000. Ensure your public site uses HTTPS and set `COOKIE_SECURE=1` in `.env`; the tunnel's internal origin can remain HTTP.

### Administrator

On first startup a strong, unique admin password is generated and persisted in the Docker volume (unless `ADMIN_PASSWORD` is supplied through `.env`). Retrieve it using:

```bash
docker compose exec -T incident-guild-ctf cat /app/data/admin-password.txt
```

For an explicit admin password use `ADMIN_PASSWORD` (at least 12 characters) in `.env`, then rebuild/restart. **Never commit `.env` or share the password with players.** In **Admin settings**, authenticate to see a password-protected overview of all players, each scenario's progress/score, flag/conclusion counts, last activity, active incident clock and common learning issues. Admin can reset all player records and scores with a second confirmation phrase. The admin endpoint has password checking and failed-attempt rate limiting.

The service name `incident-guild-ctf` and persistent Compose volume `guild_competition_data` are intentionally **unchanged** to preserve existing installation data. Do not run `docker compose down -v` unless intentionally erasing the tournament. For scoring fairness, consider using the app's admin reset between v2.0 and v2.1 tournaments; older completed scores are not silently recalculated.

## Development without Docker

Requires Node.js 22 or later, no additional packages:

```bash
cp .env.example .env
# Configure values as environment variables; Node itself does not load .env automatically.
PORT=3000 ADMIN_PASSWORD='your-long-secret-password' node server/server.cjs
```

The server stores tournament state in its `DATA_DIR` (defaults to `./data`). The local test suite uses an isolated temporary directory and HTTP port; do not point tests at your live competition.

## Safety and limitations

This is a **fictional educational simulation** with synthetic records, network data, process commands, and intentionally provided TLS inspection data. It is not connected to NetWitness production deployments. The attacker runs a predefined set of time-triggered scenario rules, not a fully autonomous red-team agent. Username-only competitions provide convenience, not strong participant identity verification. For a high-stakes tournament, add verified identity/authentication and abuse controls.
