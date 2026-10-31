# Project Structure

## Purpose

A reusable authentication and authorization server. It owns user credentials, roles and the
token lifecycle (JWT access tokens + rotating refresh tokens) so that client projects do not
implement their own.

**Deployment model: single-tenant.** The code is built into one Docker image, and every client
project gets its own container with its own database, JWT secret, roles and CORS origins.
There are no shared accounts across projects. Per-project differences live in configuration
only; the code is never copied per project.

## Tech Stack

| Area             | Technology                                                   |
|------------------|--------------------------------------------------------------|
| Runtime          | .NET 10 (`net10.0`), ASP.NET Core Web API                    |
| Identity         | ASP.NET Core Identity (`User`/`Role` with `Guid` keys)       |
| Tokens           | JWT Bearer (HMAC-SHA256), refresh tokens stored as SHA-256 hashes |
| Persistence      | Entity Framework Core 9 + SQL Server                         |
| Protection       | Account lockout, per-IP rate limiting on `/api/auth/*`       |
| API docs         | Swagger + OpenAPI (Development only)                         |
| Containerization | Dockerfile (multi-stage), docker-compose per instance + shared SQL Server |

## Directory Layout

```text
IdentityServer/                      # repository root
├── .editorconfig                    # LF, UTF-8, 2-space indent for C#
├── .gitignore                       # ignores appsettings*.json, Seed/, .env, instances/*.env
├── .dockerignore                    # keeps bin/obj, .env and instances/ out of the image
├── .env.example                     # template for .env (SQL Server SA password)
├── Dockerfile                       # SDK build stage -> aspnet runtime stage
├── docker-compose.db.yml            # shared SQL Server, started once per host
├── docker-compose.yml               # one IdentityServer instance, parameterized by an env file
├── instances/
│   ├── example.env                  # template for instances/<project>.env (git-ignored copies)
│   └── example.roles.json           # roles mounted into the container as Seed/roles.json
├── IdentityServer.sln
└── IdentityServer/                  # the single Web API project
    ├── IdentityServer.csproj
    ├── IdentityServer.http          # HTTP scratch requests (still the template stub)
    ├── Program.cs                   # configuration, DI, auth, CORS, pipeline, migration + seeding
    ├── ApplicationDbContext.cs      # IdentityDbContext + RefreshTokens DbSet
    ├── appsettings.json             # git-ignored, production config
    ├── appsettings.Development.json # git-ignored, development config
    ├── Properties/
    │   └── launchSettings.json      # http :5078, https :7066
    ├── Controllers/
    │   ├── AuthController.cs        # register / login; also defines shared DataModel
    │   ├── TokenController.cs       # refresh / validate
    │   ├── ManageController.cs      # role management (root / manager roles)
    │   └── ProfilePictureController.cs  # upload / get (ETag, 304) / delete profile picture
    ├── Filters/
    │   └── ProfilePictureUploadLimitFilter.cs  # request body + multipart limits from ProfilePicture:MaxSizeBytes
    ├── Domain/
    │   ├── Dtos/
    │   │   ├── ImageInfo.cs         # detected content type + width/height of an image
    │   │   ├── ProfilePictureMetadata.cs  # picture metadata without the image bytes
    │   │   ├── ResponseDTO.cs       # common response envelope
    │   │   ├── UserDTO.cs           # public user projection
    │   │   └── UserRoleRequest.cs   # { userId, role } body for role management
    │   ├── Entities/                # namespace: IdentityServer.Entities
    │   │   ├── User.cs              # IdentityUser<Guid> + CreatedAt, LastLogin, RefreshTokens
    │   │   ├── Role.cs              # IdentityRole<Guid>
    │   │   ├── UserClaim.cs         # IdentityUserClaim<Guid>
    │   │   ├── RefreshToken.cs      # hash, expiry, revocation, rotation chain
    │   │   └── ProfilePicture.cs    # uploaded image bytes + metadata, one per user (own table)
    │   ├── Repositories/
    │   │   └── IProfilePictureRepository.cs  # profile picture storage contract
    │   └── Services/
    │       ├── ImageContentTypes.cs # MIME types of the image formats the server can inspect
    │       ├── IProfilePictureService.cs  # profile picture service contract
    │       ├── ITokenService.cs     # token service contract
    │       ├── ProfilePictureSettings.cs  # options model for the "ProfilePicture" section
    │       ├── ProfilePictureUploadResult.cs  # upload result + validation error codes
    │       ├── RoleSettings.cs      # options model for the "Roles" section
    │       └── SeedSettings.cs      # options model for development seed users
    ├── Repositories/
    │   └── ProfilePictureRepository.cs  # EF Core storage in SQL Server, upsert without loading old bytes
    ├── Services/
    │   ├── ImageInspector.cs        # format detection by signature + width/height from JPEG/PNG/WebP headers
    │   ├── ProfilePictureService.cs # upload validation (size, format, dimensions), hashing, get / delete
    │   └── TokenService.cs          # JWT creation/validation, refresh-token lookup, rotation, revocation
    ├── Middleware/
    │   ├── RateLimitPolicies.cs     # rate limiter policy names
    │   └── RequestLoggingMiddleware.cs  # Development-only logging of JSON bodies with secrets masked
    ├── Migrations/                  # EF Core migrations (InitialCreate, AddProfilePictures)
    └── Seed/                        # git-ignored
        ├── roles.json               # "Roles" section, loaded in every environment
        └── users.json               # seed users with their roles, loaded in Development only
```

## Configuration

Sources in load order (later ones override earlier ones):

1. `appsettings.Development.json` (Development) or `appsettings.json` (other environments)
2. `Seed/roles.json` (optional, every environment)
3. `Seed/users.json` (optional, Development only)
4. Environment variables (`Section__Key`, e.g. `Security__JWTSecret`)

Missing required keys stop the application at startup with an explicit error.

### `Security`

| Key                                | Meaning                                              |
|------------------------------------|------------------------------------------------------|
| `JWTSecret`                        | HMAC signing key (at least 32 bytes)                 |
| `JWTIssuer` / `JWTAudience`        | Issuer / audience of this instance                   |
| `JWTExpiration`                    | Access token lifetime, minutes                       |
| `RTExpiration`                     | Refresh token lifetime, days                         |
| `CredentialRateLimitPermits`       | Max requests per IP to `/api/auth/*` per window      |
| `CredentialRateLimitWindowSeconds` | Rate limit window, seconds                           |
| `LockoutMaxFailedAttempts`         | Failed password attempts before account lockout      |
| `LockoutDurationMinutes`           | Account lockout duration, minutes                    |
| `LockoutAllowedForNewUsers`        | Whether newly created users can be locked out        |
| `Password`                         | Identity `PasswordOptions`: `RequiredLength`, `RequiredUniqueChars`, `RequireDigit`, `RequireLowercase`, `RequireUppercase`, `RequireNonAlphanumeric` |
| `AllowedOrigins`                   | CORS origins allowed to call the API from a browser; empty blocks all |

Plus `ConnectionStrings:DefaultConnection` for SQL Server.

### `Roles`

| Key         | Meaning                                                                |
|-------------|------------------------------------------------------------------------|
| `Available` | Every role of the instance; all are created at startup                 |
| `Initial`   | Role assigned on registration; must not be root or a manager role      |
| `Root`      | Role with absolute rights; only its holders can grant or revoke it     |
| `Managers`  | Roles that can grant or revoke ordinary roles (not root, not managers) |

What each role is allowed to do inside a client project is decided by that project from the
role claims in the JWT.

### `ProfilePicture`

| Key                       | Meaning                                                                 |
|---------------------------|-------------------------------------------------------------------------|
| `MaxSizeBytes`            | Max upload size, bytes                                                  |
| `MinWidth` / `MinHeight`  | Min image dimensions, pixels                                            |
| `MaxWidth` / `MaxHeight`  | Max image dimensions, pixels; must not be less than the minimums        |
| `AllowedContentTypes`     | Non-empty subset of `image/jpeg`, `image/png`, `image/webp`             |

### `Seed` (Development only)

`Seed:Users[]` with `Username`, `Email`, `Password`, `Roles[]`. The seed defines the exact
role set of each seeded user; users with roles missing from `Roles:Available` are skipped.

## HTTP API

| Method | Route                                  | Auth                    | Description |
|--------|----------------------------------------|-------------------------|-------------|
| POST   | `/api/auth/register`                   | none, rate limited      | Creates a user with `Roles:Initial`, returns user + tokens |
| POST   | `/api/auth/login`                      | none, rate limited      | Logs in by `username`+`password`, `email`+`password`, or `accessToken`/`refreshTokenHash` |
| POST   | `/api/token/refresh`                   | none                    | Rotates a refresh token and issues a new access token |
| POST   | `/api/token/validate`                  | none                    | Validates an access token passed as a raw JSON string body |
| POST   | `/api/manage/assignRole`               | root or manager         | Body `{ userId, role }`; assigns a role from `Roles:Available` |
| POST   | `/api/manage/removeRole`               | root or manager         | Body `{ userId, role }`; the last root holder cannot lose the root role |
| GET    | `/api/manage/userRoles?userId=`        | self, root or manager   | Lists the user's roles |
| GET    | `/api/manage/hasRole?userId=&role=`    | self, root or manager   | Returns whether the user has the role |
| PUT    | `/api/profilePicture`                  | any authenticated user  | Multipart field `file`; replaces the caller's picture, returns its metadata |
| GET    | `/api/profilePicture/{userId}`         | none                    | Image bytes with `ETag`/`Last-Modified`; `If-None-Match` gives 304 |
| DELETE | `/api/profilePicture`                  | any authenticated user  | Deletes the caller's picture; 404 if there is none |
| DELETE | `/api/profilePicture/{userId}`         | root or manager         | Moderation: deletes a user's picture (cannot replace it); managers cannot target root or manager holders; logged |

Profile picture uploads are checked against the `ProfilePicture` section: the format is detected
from the file signature (the client file name and Content-Type are ignored), then the format and
dimensions are validated. Oversized uploads are rejected while reading: 413 from the service, or
400 if the multipart body exceeds the limit before the file reaches it. Pictures are served with
`X-Content-Type-Options: nosniff` and a sandboxing `Content-Security-Policy`.

`refreshTokenHash` in request bodies carries the raw refresh token despite its name.

## Token Model

- **Access token**: JWT with `sub` (user id), `jti`, `ClaimTypes.Name`, `sstamp` (SHA-256 of
  the user's security stamp) and one `ClaimTypes.Role` per role. Validated with the singleton `TokenValidationParameters`
  registered in `Program.cs` (1 minute clock skew). JWT Bearer is the default authentication
  scheme (overriding the cookie defaults set by `AddIdentity`).
- **Refresh token**: 64 random bytes. The client receives the raw value; only its SHA-256 hash
  is stored. Every password login creates an independent session (token).
- **Rotation**: the old token is revoked by a conditional `UPDATE` inside a transaction, so of
  several concurrent requests with the same token only one succeeds.
- **Reuse detection**: presenting an already revoked token revokes all active refresh tokens
  of its user and changes their security stamp.
- **Security stamp**: every access token check (JWT Bearer `OnTokenValidated` and
  `/api/token/validate`) compares `sstamp` with the user's current stamp. Role changes and
  reuse detection change the stamp, so access tokens issued before them are rejected at once
  (costs one user lookup per authenticated request).

## Request Pipeline (Program.cs order)

`RequestLoggingMiddleware`, OpenAPI, Swagger (Development only) → HttpsRedirection → Routing →
CORS → RateLimiter → Authentication → Authorization → MapControllers.

## Deployment

```bash
docker network create shared-network                     # once per host
cp .env.example .env                                     # set MSSQL_SA_PASSWORD
docker compose -f docker-compose.db.yml up -d            # shared SQL Server, once per host
cp instances/example.env instances/<project>.env         # per project: port, DB, secrets, origins
docker compose --env-file instances/<project>.env up -d --build
```

Each instance needs its own `COMPOSE_PROJECT_NAME`, `AUTH_PORT`, database name, `JWTSecret`
and roles file.

## Known Issues

Tracked in code with `FIXME:` / `TODO:` (see `AGENTS.md`). Open items:

- Internal exception messages are returned to the client (`AuthController`, `TokenController`).
- `User.LastLogin` is never updated on login.
- Microsoft package versions are 9.0.x while the target framework is `net10.0`.
- `DataModel.RefreshTokenHash` should be renamed to `RefreshToken` (public contract change).
- Refresh tokens have no `FamilyId`, so reuse detection revokes every session of the user.
- Rate limiting by IP needs `ForwardedHeaders` behind a reverse proxy.
- `appsettings.json` is git-ignored, so an image built from a fresh clone cannot start in Production.
- All instances connect to SQL Server as `sa`; a dedicated login per instance is preferable.
- No logout endpoint and no cleanup of expired/revoked refresh tokens yet.
