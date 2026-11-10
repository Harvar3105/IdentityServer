# IdentityServer

A reusable authentication and authorization server: user accounts, roles, JWT access tokens and
rotating refresh tokens. One Docker image is deployed as a separate container per client project,
each with its own database and configuration.

- Architecture, configuration keys and HTTP API: [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
- Running tests and code coverage: [TESTING.md](TESTING.md)

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download) — for local runs and tests
- [Docker](https://docs.docker.com/get-docker/) with Docker Compose — for SQL Server and deployment

## Configuration files

All configuration of an instance lives in [instances/](instances/). Only the templates are committed;
the real files are git-ignored.

| Real file (git-ignored)                  | Template                                                   | Purpose                                                    |
|------------------------------------------|------------------------------------------------------------|------------------------------------------------------------|
| `instances/.env`                         | [example.env](instances/example.env)                       | Docker Compose: port, environment, SQL Server mode and logins |
| `instances/appsettings.json`             | [appsettingsExample.json](instances/appsettingsExample.json) | Application settings in Production                       |
| `instances/appsettings.Development.json` | [appsettingsExample.json](instances/appsettingsExample.json) | Application settings in Development                      |
| `instances/roles.json`                   | [rolesExample.json](instances/rolesExample.json)           | Roles of the instance, every environment                   |
| `instances/users.json`                   | [usersExample.json](instances/usersExample.json)           | Seed users, Development only (optional)                    |

How the files reach the application:

- **Local run** (`dotnet run`): the build copies `instances/*.json` to `config/` next to the binaries.
  Restart the server after editing them.
- **Docker**: `docker-compose.yml` mounts `instances/` into the container as `/app/config`, so the image
  contains no configuration. Restart the container after editing them.

The application stops at startup with an explicit error if a required key is missing.

### Values to change

- `instances/.env`
  - `AUTH_PORT` — host port of the server.
  - `MSSQL_SA_PASSWORD` — SQL Server administrator password; only used to create `DB_USER`.
  - `DB_USER` / `DB_PASSWORD` — the login the application connects with. It is created (or its password
    updated) on every `docker compose up` and gets the `dbcreator` role, so it creates and owns its
    database on the first start. Must match `User Id` and `Password` in the connection strings of
    `appsettings*.json`, and must not contain `'`.
  - `COMPOSE_PROFILES`, `DB_PORT`, `DB_EDITION` — mode, host port and edition of the SQL Server, see
    [SQL Server modes](#sql-server-modes).
- `instances/appsettings*.json`
  - `ConnectionStrings:DefaultConnection` — the host is `sqlserver` when the server runs in Docker
    and `localhost,<DB_PORT>` when it runs with `dotnet run`.
  - `Security:JWTSecret` — a unique random value of at least 32 bytes, e.g. `openssl rand -base64 48`.
  - `Security:JWTIssuer` / `Security:JWTAudience` — the values the client project validates.
  - `Security:AllowedOrigins` — browser origins of the client project.
  - `Security:TrustedProxies` — addresses of the client project's BFF (or reverse proxy) that forwards
    the user's IP in `X-Forwarded-For`; without it every user shares the BFF's rate limit. Only the
    rightmost header entry is used, and only for requests from these addresses. List exact addresses:
    a network such as the whole `shared-network` subnet also trusts every other container on it and,
    for the published `AUTH_PORT`, possibly the Docker gateway, so their callers could spoof their IP.
    For `dotnet run` with a BFF on the same machine use `[ "127.0.0.1", "::1" ]`.
- `instances/roles.json` and `instances/users.json` — every seed user role must be listed in
  `Roles:Available`, and seed passwords must satisfy `Security:Password`.

Any key can also be overridden by an environment variable with `__` between sections,
e.g. `Security__JWTExpiration=30`.

## Quick start

Run from the repository root (Bash or Git Bash).

### 1. Create the configuration

```bash
cp instances/example.env instances/.env
cp instances/appsettingsExample.json instances/appsettings.json
cp instances/appsettingsExample.json instances/appsettings.Development.json
cp instances/rolesExample.json instances/roles.json
cp instances/usersExample.json instances/users.json
```

Then edit the copies as described in [Values to change](#values-to-change).
For a local run, set the host in `appsettings.Development.json` to `localhost,<DB_PORT>`.

### 2a. Run in Docker

The server and its SQL Server run in one compose stack named `identityserver`:

```bash
docker network create shared-network 2>/dev/null || true
docker compose --env-file instances/.env up -d --build
```

`shared-network` lets containers of client projects reach the server as `authserver:8080`; the
database is only on the stack's own network.

The SQL Server starts first, then `sqlserver-init` creates `DB_USER`, then the server starts, applies
migrations and creates the roles. The server listens on `http://localhost:<AUTH_PORT>`. With
`ASPNETCORE_ENVIRONMENT=Development` in `instances/.env`, seed users are created and Swagger UI is
available at `http://localhost:<AUTH_PORT>/swagger`.

Useful commands:

```bash
docker compose --env-file instances/.env logs -f authserver   # server logs
docker compose --env-file instances/.env restart authserver   # apply configuration changes
docker compose --env-file instances/.env down                 # stop the stack (data is kept in persistent mode)
```

#### SQL Server modes

`COMPOSE_PROFILES` in `instances/.env` selects how the stack runs the SQL Server:

| Mode         | Data                                                         | Restart              |
|--------------|--------------------------------------------------------------|----------------------|
| `persistent` | kept in the `identityserver_sqlserver_data` volume           | with Docker          |
| `test`       | inside the container; `down` deletes all databases           | no                   |
| empty        | no SQL Server in the stack; connection strings point to an external one | —     |

In both modes the database is reachable as `sqlserver`, so connection strings do not change. Stop the
stack before switching modes:

```bash
docker compose --env-file instances/.env down
# change COMPOSE_PROFILES in instances/.env
docker compose --env-file instances/.env up -d
```

A database created earlier by another login (e.g. `sa`) is not accessible to `DB_USER`; drop it or
grant access to it manually.

`MSSQL_SA_PASSWORD` only takes effect when the `identityserver_sqlserver_data` volume is created. If
`sqlserver-init` fails with `Login failed for user 'sa'`, the volume was created with another password:
put that password into `instances/.env`, or remove the volume (`docker volume rm identityserver_sqlserver_data`,
deletes all databases) so that it is created again.

### 2b. Or run locally

Start only the SQL Server from the stack, then the server with `dotnet run`:

```bash
docker network create shared-network 2>/dev/null || true
docker compose --env-file instances/.env up -d sqlserver sqlserver-init      # sqlserver-test in test mode
dotnet run --project IdentityServer --launch-profile http
```

Swagger UI: <http://localhost:5078/swagger>. Use `--launch-profile https` to also listen on
`https://localhost:7066`.

### 3. Check that it works

```bash
curl -X POST http://localhost:5078/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"Passw0rd1"}'
```

For Docker, replace `5078` with `AUTH_PORT`.
