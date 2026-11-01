# IdentityServer

A reusable authentication and authorization server: user accounts, roles, JWT access tokens and
rotating refresh tokens. One Docker image is deployed as a separate container per client project,
each with its own database and configuration.

- Architecture, configuration keys and HTTP API: [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
- Running tests and code coverage: [TESTING.md](TESTING.md)

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download) — for local runs and tests
- [Docker](https://docs.docker.com/get-docker/) with Docker Compose — for SQL Server and deployment

## Files that are not in the repository

Configuration files contain secrets and are git-ignored. Create them before the first run:

| File                                          | Needed for         | Template                                     |
|-----------------------------------------------|--------------------|----------------------------------------------|
| `IdentityServer/appsettings.Development.json` | local run          | [below](#appsettingsdevelopmentjson)         |
| `IdentityServer/appsettings.json`             | Docker image       | [below](#appsettingsjson)                    |
| `IdentityServer/Seed/roles.json`              | local run          | [instances/example.roles.json](instances/example.roles.json) |
| `IdentityServer/Seed/users.json`              | local run, optional | [below](#seedusersjson)                     |
| `.env`                                        | shared SQL Server  | [.env.example](.env.example)                 |
| `instances/<project>.env`                     | Docker instance    | [instances/example.env](instances/example.env) |
| instance application settings                 | Docker instance    | [instances/applicationExample.json](instances/applicationExample.json) |

The application stops at startup with an explicit error if a required key is missing.

### `appsettings.Development.json`

Loaded when `ASPNETCORE_ENVIRONMENT=Development` (the default for `dotnet run`).
The password in the connection string must match `MSSQL_SA_PASSWORD` from `.env`.

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost,1433;Database=IdentityServerDB;User Id=sa;Password=CHANGE_ME_Strong!Passw0rd;TrustServerCertificate=true;"
  },
  "Security": {
    "JWTSecret": "CHANGE_ME_at_least_32_random_characters",
    "JWTIssuer": "identity-dev",
    "JWTAudience": "dev",
    "JWTExpiration": 15,
    "RTExpiration": 7,
    "CredentialRateLimitPermits": 10,
    "CredentialRateLimitWindowSeconds": 60,
    "LockoutMaxFailedAttempts": 5,
    "LockoutDurationMinutes": 15,
    "LockoutAllowedForNewUsers": true,
    "Password": {
      "RequiredLength": 8,
      "RequiredUniqueChars": 0,
      "RequireDigit": true,
      "RequireLowercase": true,
      "RequireUppercase": true,
      "RequireNonAlphanumeric": false
    },
    "AllowedOrigins": [ "http://localhost:3000" ]
  },
  "ProfilePicture": {
    "MaxSizeBytes": 2097152,
    "MinWidth": 64,
    "MinHeight": 64,
    "MaxWidth": 2048,
    "MaxHeight": 2048,
    "AllowedContentTypes": [ "image/jpeg", "image/png", "image/webp" ]
  },
  "AllowedHosts": "*"
}
```

`JWTSecret` must be at least 32 bytes. Generate one with `openssl rand -base64 48`.

### `appsettings.json`

Loaded in every non-Development environment. The `Dockerfile` copies it into the image, so the image
cannot start without it, and **it must not contain secrets**: keep only the shared defaults here and
pass the connection string, `JWTSecret`, issuer, audience and CORS origins through
`instances/<project>.env`.

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "Security": {
    "JWTExpiration": 15,
    "RTExpiration": 7,
    "CredentialRateLimitPermits": 10,
    "CredentialRateLimitWindowSeconds": 60,
    "LockoutMaxFailedAttempts": 5,
    "LockoutDurationMinutes": 15,
    "LockoutAllowedForNewUsers": true,
    "Password": {
      "RequiredLength": 8,
      "RequiredUniqueChars": 0,
      "RequireDigit": true,
      "RequireLowercase": true,
      "RequireUppercase": true,
      "RequireNonAlphanumeric": false
    }
  },
  "ProfilePicture": {
    "MaxSizeBytes": 2097152,
    "MinWidth": 64,
    "MinHeight": 64,
    "MaxWidth": 2048,
    "MaxHeight": 2048,
    "AllowedContentTypes": [ "image/jpeg", "image/png", "image/webp" ]
  },
  "AllowedHosts": "*"
}
```

Any key can be overridden by an environment variable with `__` between sections,
e.g. `Security__JWTExpiration=30`.

### `Seed/roles.json`

Defines the roles of the instance; all of them are created at startup. Copy the template:

```bash
mkdir -p IdentityServer/Seed
cp instances/example.roles.json IdentityServer/Seed/roles.json
```

In Docker this file is not used: the instance mounts its own roles file (`ROLES_FILE` in
`instances/<project>.env`) over `/app/Seed/roles.json`.

### `Seed/users.json`

Optional, loaded in Development only. Users are created at startup with exactly the listed roles;
every role must be in `Roles:Available`, and passwords must satisfy `Security:Password`.

```json
{
  "Seed": {
    "Users": [
      {
        "Username": "admin",
        "Email": "admin@example.com",
        "Password": "CHANGE_ME_Admin1",
        "Roles": [ "ADMIN" ]
      },
      {
        "Username": "user",
        "Email": "user@example.com",
        "Password": "CHANGE_ME_User1",
        "Roles": [ "USER" ]
      }
    ]
  }
}
```

## Running locally

All commands are run from the repository root.

1. Start SQL Server in Docker (skip if you use your own SQL Server and adjust the connection string):

   ```bash
   docker network create shared-network
   cp .env.example .env          # set MSSQL_SA_PASSWORD
   docker compose -f docker-compose.db.yml up -d
   ```

2. Create `appsettings.Development.json`, `Seed/roles.json` and, optionally, `Seed/users.json`
   as described above.

3. Run the server:

   ```bash
   dotnet run --project IdentityServer --launch-profile http
   ```

   Migrations are applied and roles/seed users are created automatically at startup.
   Use `--launch-profile https` to also listen on `https://localhost:7066`.

4. Open Swagger UI at <http://localhost:5078/swagger>.

Check that the server works by registering a user:

```bash
curl -X POST http://localhost:5078/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"Passw0rd1"}'
```

## Running in Docker

Every client project gets its own container, database and env file; all instances share one
SQL Server per host.

1. Once per host, start the shared SQL Server:

   ```bash
   docker network create shared-network
   cp .env.example .env          # set MSSQL_SA_PASSWORD
   docker compose -f docker-compose.db.yml up -d
   ```

2. Create `IdentityServer/appsettings.json` as described above (it is baked into the image).

3. For each client project, create its env file and roles file:

   ```bash
   cp instances/example.env instances/<project>.env
   cp instances/example.roles.json instances/<project>.roles.json
   ```

   In `instances/<project>.env` set at least:

   | Variable                                | Value                                                        |
   |-----------------------------------------|--------------------------------------------------------------|
   | `COMPOSE_PROJECT_NAME`                  | unique per instance, e.g. `<project>-auth`                   |
   | `INSTANCE_ENV_FILE`                     | `instances/<project>.env`                                    |
   | `ROLES_FILE`                            | `./instances/<project>.roles.json`                           |
   | `AUTH_PORT`                             | free host port, unique per instance                          |

   A literal `$` in a value must be written as `$$`.

   Instance application settings are templated in
   [instances/applicationExample.json](instances/applicationExample.json):

   | Key                                     | Value                                                        |
   |-----------------------------------------|--------------------------------------------------------------|
   | `ConnectionStrings:DefaultConnection`   | `Server=sqlserver,1433;...` with a unique `Database` name and the password from `.env` |
   | `Security:JWTSecret`                    | unique random value, at least 32 characters                  |
   | `Security:JWTIssuer` / `Security:JWTAudience` | issuer / audience the client project validates         |
   | `Security:AllowedOrigins`               | browser origins of the client project                        |

   > **Not wired yet:** `docker-compose.yml` does not pass this JSON file to the container. Until it does,
   > set these keys as environment variables in `instances/<project>.env` (`__` between sections, e.g.
   > `Security__JWTSecret=...`, `Security__AllowedOrigins__0=https://...`).

4. Build and start the instance:

   ```bash
   docker compose --env-file instances/<project>.env up -d --build
   ```

   The server listens on `http://localhost:<AUTH_PORT>`. Swagger is not available outside Development.

Useful commands:

```bash
docker compose --env-file instances/<project>.env logs -f      # logs
docker compose --env-file instances/<project>.env down         # stop the instance
```
