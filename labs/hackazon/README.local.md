# Hackazon Local Lab

Vulnerable target for local scanner testing.

```powershell
docker compose -f labs\hackazon\docker-compose.yml up -d --build
```

Open:

- App: http://localhost:8081/
- Installer if needed: http://localhost:8081/install

Default app login from the original project docs:

- `admin` / `hackazon`

Stop:

```powershell
docker compose -f labs\hackazon\docker-compose.yml down
```

Reset DB:

```powershell
docker compose -f labs\hackazon\docker-compose.yml down -v
docker compose -f labs\hackazon\docker-compose.yml up -d --build
```
