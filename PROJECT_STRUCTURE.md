# Project Structure

## Purpose

A reusable, standalone authentication and authorization server. It owns user credentials,
roles and the token lifecycle (JWT access tokens + rotating refresh tokens) so that multiple
client projects can share one identity backend instead of implementing their own.

Client projects identify themselves with a `Project` request header carrying the project's
API key; the key determines which initial role a newly registered user receives.

## Tech Stack

| Area            | Technology                                                    |
|-----------------|---------------------------------------------------------------|
| Runtime         | .NET 10 (`net10.0`), ASP.NET Core Web API                     |
| Identity        | ASP.NET Core Identity (`User`/`Role` with `Guid` keys)        |
| Tokens          | JWT Bearer (HMAC-SHA256), custom refresh tokens stored in DB  |
| Persistence     | Entity Framework Core 9 + SQL Server                          |
| API docs        | Swagger (Swashbuckle) + built-in OpenAPI (Development only)   |
| Containerization| Dockerfile (multi-stage) + docker-compose (SQL Server 2022)   |

`Duende.IdentityServer` is referenced but currently used only for the `IsNullOrEmpty()`
string extension; the server does not use Duende's OAuth/OIDC pipeline.

## Directory Layout

```
IdentityServer/                      # repository root
├── .editorconfig                    # LF, UTF-8, 2-space indent for C#
├── .gitignore                       # also ignores appsettings*.json, Migrations/, Seed/
├── Dockerfile                       # SDK build stage -> aspnet runtime stage
├── docker-compose.yml               # sqlserver + authserver on external "shared-network"
├── IdentityServer.sln
└── IdentityServer/                  # the single Web API project
    ├── IdentityServer.csproj
    ├── IdentityServer.http          # HTTP scratch requests (still the template stub)
    ├── Program.cs                   # DI, auth, CORS, pipeline, DB migration + seeding
    ├── ApplicationDbContext.cs      # IdentityDbContext + RefreshTokens DbSet
    ├── appsettings.json             # git-ignored, production config
    ├── appsettings.Development.json # git-ignored, development config
    ├── Properties/
    │   └── launchSettings.json      # http :5078, https :7066
    ├── Controllers/
    │   ├── AuthController.cs        # register / login; also defines shared DataModel
    │   ├── TokenController.cs       # refresh / validate
    │   └── ManageController.cs      # role management for ADMIN users
    ├── Domain/
    │   ├── Dtos/
    │   │   ├── ResponseDTO.cs       # common response envelope
    │   │   └── UserDTO.cs           # public user projection
    │   ├── Entities/                # namespace: IdentityServer.Entities
    │   │   ├── User.cs              # IdentityUser<Guid> + CreatedAt, LastLogin, RefreshTokens
    │   │   ├── Role.cs              # IdentityRole<Guid>
    │   │   ├── UserClaim.cs         # IdentityUserClaim<Guid>
    │   │   └── RefreshToken.cs      # hash, expiry, revocation, rotation chain
    │   └── Services/
    │       ├── ITokenService.cs     # token service contract
    │       └── SeedSettings.cs      # options model for Seed/seedsettings.json
    ├── Services/
    │   └── TokenService.cs          # JWT creation/validation, refresh-token rotation
    ├── Middleware/
    │   └── RequestLoggingMiddleware.cs  # Development-only request/response logging
    ├── Migrations/                  # git-ignored EF Core migrations (InitialCreate)
    └── Seed/
        └── seedsettings.json        # git-ignored projects, roles, API keys, seed users
```

## Configuration

Loaded in `Program.cs`: `appsettings.Development.json` (Development) or `appsettings.json`
(other environments), then environment variables, then `Seed/seedsettings.json`.

| Key                                   | Meaning                                  |
|---------------------------------------|------------------------------------------|
| `ConnectionStrings:DefaultConnection` | SQL Server connection string             |
| `Security:JWTSecret`                  | HMAC signing key                         |
| `Security:JWTIssuer` / `JWTAudience`  | Expected issuer / audience               |
| `Security:JWTExpiration`              | Access token lifetime, minutes           |
| `Security:RTExpiration`               | Refresh token lifetime, days             |
| `Security:CredentialRateLimitPermits` | Max requests per IP to `/api/auth/*` per window |
| `Security:CredentialRateLimitWindowSeconds` | Rate limit window, seconds         |
| `Security:LockoutMaxFailedAttempts`   | Failed password attempts before account lockout |
| `Security:LockoutDurationMinutes`     | Account lockout duration, minutes        |
| `Seed:Projects[]`                     | `Name`, `API_KEY`, `Roles { Admin[], User[], Initial }` |
| `Seed:Users[]`                        | `Username`, `Email`, `Password`, `Roles[]` |

On startup `SetupAppData` applies EF migrations (unless the provider is InMemory), creates
every role declared by the seeded projects, and creates/updates the seeded users.

## HTTP API

All routes are prefixed with `api/[controller]`.

| Method | Route                  | Auth   | Description |
|--------|------------------------|--------|-------------|
| POST   | `/api/auth/register`   | none + `Project` header | Creates a user, assigns the project's initial role, returns user + tokens |
| POST   | `/api/auth/login`      | none   | Logs in by `username`+`password`, `email`+`password`, or `accessToken`/`refreshTokenHash` |
| POST   | `/api/token/refresh`   | none   | Rotates a refresh token and issues a new access token |
| POST   | `/api/token/validate`  | none   | Validates an access token passed as a raw JSON string body |
| —      | `/api/manage/*`        | `ADMIN` (partly) | `AsignRole`, `RemoveRole`, `GetUserRoles`, `CheckUserRole` — no HTTP verb/route attributes yet |

## Token Model

- **Access token**: JWT with `sub` (user id), `jti`, `ClaimTypes.Name`, and one
  `ClaimTypes.Role` per role. Validated with the singleton `TokenValidationParameters`
  registered in `Program.cs` (1 minute clock skew).
- **Refresh token**: 64 random bytes, SHA-256 hashed and stored in `RefreshTokens`.
  Rotation revokes the old token (`RevokedAt`, `RevokedByIp`, `ReplacedByTokenHash`)
  and stores a new one. Deleted in cascade with the user.

## Request Pipeline (Program.cs order)

`RequestLoggingMiddleware` (Dev) → OpenAPI (Dev) → Swagger → Routing → Authentication →
Authorization → MapControllers → HttpsRedirection → CORS (`AllowAll`).

## Known Issues Found During Review

These should be marked in code with `FIXME:` / `TODO:` as they are addressed (see `AGENTS.md`).

- `ManageController` actions have no `[HttpPost]`/`[HttpGet]` attributes, so they are not
  reachable as intended; `GetUserRoles` and `CheckUserRole` have no `[Authorize]`.
- The refresh token returned to clients is the stored **hash**; the raw token is discarded,
  so a database leak exposes usable refresh tokens.
- `AuthController.Register` validates the `Project` header **after** the user is created.
- `SetupAppData` calls `AddToRolesAsync(parsed, ...)` on the unsaved object instead of
  `existingUser`, and does not remove roles absent from the seed.
- `TryLogin` rotates the latest refresh token even if it is already revoked/expired;
  `LastLogin` is never updated on login.
- `RequestLoggingMiddleware` logs request bodies, including plain-text passwords.
- CORS and HTTPS redirection are registered after `MapControllers`; CORS allows any origin.
- Password policy requires only 4 characters.
- `docker-compose.yml` contains a hard-coded SA password.
- Microsoft package versions are 9.0.x while the target framework is `net10.0`.
- Two unrelated `DataModel` classes exist (`AuthController` and nested in `ManageController`);
  `ResponseDTO.IsAaccessTokenValid` is misspelled; `IdentityServer.http` is a template stub.
- Namespace `IdentityServer.Entities` does not match folder `Domain/Entities`;
  `SeedSettings` is an options model located under `Domain/Services`.
