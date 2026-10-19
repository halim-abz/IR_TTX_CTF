# Quick start — The War Room: Incident Response v2.1

See `README.md` for complete Ubuntu, Docker Desktop, Cloudflare Tunnel, and administration instructions.

```bash
# From the project directory on Ubuntu (Docker Desktop)
docker context use desktop-linux
docker compose up -d --build
docker compose ps
```

Visit `http://localhost:3030`, or your existing HTTPS domain served through Cloudflare Tunnel. For separate Docker Desktop tunnel containers, the origin is normally `http://host.docker.internal:3030`.

Retrieve the installation-specific admin password when no explicit ADMIN_PASSWORD is configured:

```bash
docker compose exec -T incident-guild-ctf cat /app/data/admin-password.txt
```

Each player must inspect two flag records, submit two mandatory forensic flags and substantiate two conclusions before verified closure. The after-action review explains both good and poor practices.

Upgrades preserve the existing Docker volume. Reset the competition through Admin settings when you want every player to start again under the updated scoring rules.
