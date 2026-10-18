# Incident Trace CTF · V5-based multiplayer · four-stage — Quick Ubuntu test

The v5 game engine, usernames, scoreboard and admin reset remain unchanged. The updated interface has four navigation destinations.

## Docker Desktop on Ubuntu

```bash
# Run from the directory with docker-compose.yml (no sudo)
docker context use desktop-linux
# Optional, only if you do not already have a .env file:
cp -n .env.example .env
# If you access through Cloudflare HTTPS, edit .env and set COOKIE_SECURE=1
docker compose up -d --build
docker compose ps
```

Local game address: **http://localhost:3030**. With your existing Cloudflare Tunnel container, the HTTP origin is commonly **http://host.docker.internal:3030**.

## Default administrator password

The first time the server starts without an ADMIN_PASSWORD environment variable, it generates a *unique private default password* for that installation and saves it to the persistent data volume.

```bash
# Print the auto-generated admin password without restarting anything
docker compose exec -T incident-guild-ctf cat /app/data/admin-password.txt
```

The password is also shown in `docker compose logs`. If your existing `.env` specifies `ADMIN_PASSWORD`, **use that configured password instead**; the auto-generated file is not created. Do not commit `.env` or `data/` to GitHub.

Admin tools are available via the settings icon. Admin reset still requires typing `RESET EVERYTHING`.

## Updating an existing competition

Copy the new project source into your Git repository, excluding private `.env` and `data/` from commits. On Ubuntu, `git pull` and run `docker compose up -d --build`. Existing leaderboard records are preserved in the named Docker volume. Never use `docker compose down -v` unless intentionally discarding data.

## Testing notes

This assistant executed the Node.js application and browser checks locally. The sandbox cannot publish a persistent public server address. To let other players connect, use your own Ubuntu Docker Desktop server and Cloudflare Tunnel.

## Upgrading a previous tournament

This release adds a fourth scenario and changes scoring. If you want to compare players fairly, reset the competition through Admin settings after replacing the application files and rebuilding. Existing data is retained unless you deliberately reset it.

The **Docker service name** remains `incident-guild-ctf` and **volume name** remains `guild_competition_data` for backward compatibility. These are internal deployment identifiers, not the product name.
