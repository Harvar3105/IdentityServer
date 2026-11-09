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
| Containerization | Dockerfile (multi-stage), one compose stack: server + SQL Server |
| Tests            | xUnit + EF Core SQLite in-memory                             |

## Directory Layout

```text
IdentityServer/                      # repository root
├── .editorconfig                    # LF, UTF-8, 2-space indent for C#
├── .gitignore                       # ignores everything in instances/ except the templates
├── .dockerignore                    # keeps bin/obj, instances/ and appsettings*.json out of the image
├── Dockerfile                       # SDK build stage -> aspnet runtime stage
├── docker/
│   └── sqlserver/
│       └── create-login.sql         # creates the application login DB_USER with the dbcreator role
├── docker-compose.yml               # stack "identityserver": server (mounts instances/ as /app/config) + SQL Server
├── instances/                       # instance configuration; real files are git-ignored
│   ├── example.env                  # template for .env: compose project name, port, environment, SA password
│   ├── appsettingsExample.json      # template for appsettings.json / appsettings.Development.json
│   ├── rolesExample.json            # template for roles.json: "Roles" section, every environment
│   └── usersExample.json            # template for users.json: seed users, Development only
├── IdentityServer.sln
├── README.md                        # required local files, local run and Docker deployment
├── TESTING.md                       # how to run tests and collect code coverage
├── IdentityServer.Tests/            # xUnit tests (`dotnet test`), not part of the Docker image
│   └── Unit/                        # unit tests; folders mirror the Web API project
│       ├── Entities/
│       │   └── RefreshTokenTests.cs # IsExpired / IsActive
│       └── Services/
│           ├── TokenServiceFixture.cs    # real TokenService + Identity on SQLite in-memory (ExecuteUpdate support)
│           ├── TokenServiceAccessTokenTests.cs   # JWT claims, signature/issuer/audience/alg/lifetime checks, security stamp
│           └── TokenServiceRefreshTokenTests.cs  # hashing, lookup, rotation, sessions, logout, reuse detection
└── IdentityServer/                  # the Web API project
    ├── IdentityServer.csproj        # copies instances/*.json (except templates) to config/ in the output
    ├── Program.cs                   # configuration, DI, auth, CORS, pipeline, migration + seeding
    ├── ApplicationDbContext.cs      # IdentityDbContext + RefreshTokens DbSet
    ├── Properties/
    │   └── launchSettings.json      # http :5078, https :7066
    ├── Controllers/
    │   ├── Contracts/               # per-endpoint request and response contracts
    │   │   ├── RegisterRequest.cs   # { username, email, password }
    │   │   ├── LoginRequest.cs      # { username | email, password }
    │   │   ├── SessionRequest.cs    # { accessToken?, refreshToken? }, at least one
    │   │   ├── LogoutRequest.cs     # { refreshToken } body for logout
    │   │   ├── RefreshRequest.cs    # { refreshToken }
    │   │   ├── ValidateTokenRequest.cs  # { accessToken }
    │   │   ├── AuthResponse.cs      # register / login: user, roles, new token pair
    │   │   ├── SessionResponse.cs   # session: user, roles, rotated token pair if the refresh token was used
    │   │   ├── TokenPairResponse.cs # refresh: rotated token pair
    │   │   ├── ValidateTokenResponse.cs  # validate: { valid }
    │   │   ├── UserRoleRequest.cs   # { userId, role } body for assignRole / removeRole
    │   │   ├── UserRolesQuery.cs    # ?userId= for userRoles
    │   │   ├── HasRoleQuery.cs      # ?userId=&role= for hasRole
    │   │   ├── UserRolesResponse.cs # { userId, roles }
    │   │   └── HasRoleResponse.cs   # { hasRole }
    │   ├── AuthController.cs        # register / login / session / logout / logoutAll
    │   ├── TokenController.cs       # refresh / validate
    │   ├── ManageController.cs      # role management (root / manager roles)
    │   └── ProfilePictureController.cs  # upload / get (ETag, 304) / delete profile picture
    ├── Filters/
    │   └── ProfilePictureUploadLimitFilter.cs  # request body + multipart limits from ProfilePicture:MaxSizeBytes
    ├── Domain/
    │   ├── Dtos/
    │   │   ├── ImageInfo.cs         # detected content type + width/height of an image
    │   │   ├── ProfilePictureMetadata.cs  # picture metadata without the image bytes
    │   │   └── UserDTO.cs           # public user projection
    │   ├── Entities/                # namespace: IdentityServer.Entities
    │   │   ├── User.cs              # IdentityUser<Guid> + CreatedAt, LastLogin, RefreshTokens
    │   │   ├── Role.cs              # IdentityRole<Guid>
    │   │   ├── UserClaim.cs         # IdentityUserClaim<Guid>
    │   │   ├── RefreshToken.cs      # hash, expiry, revocation, rotation chain, SessionId
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
    │   └── TokenService.cs          # JWT creation/validation, refresh-token lookup, rotation, session revocation
    ├── Middleware/
    │   ├── RateLimitPolicies.cs     # rate limiter policy names
    │   └── RequestLoggingMiddleware.cs  # Development-only logging of JSON bodies with secrets masked
    └── Migrations/                  # EF Core migrations (InitialCreate, AddProfilePictures, MapUserClaimsNavigation,
                                     # AddRefreshTokenSessionId, MakeEmailIndexUnique)
```

## Configuration

Files are read from `config/` next to the binaries: a local build copies `instances/*.json` there,
and `docker-compose.yml` mounts `instances/` there. Sources in load order (later ones override
earlier ones):

1. `appsettings.Development.json` (Development) or `appsettings.json` (other environments)
2. `roles.json` (optional, every environment)
3. `users.json` (optional, Development only)
4. Environment variables (`Section__Key`, e.g. `Security__JWTSecret`)

Missing required keys stop the application at startup with an explicit error.

### `Security`

| Key                                | Meaning                                              |
|------------------------------------|------------------------------------------------------|
| `JWTSecret`                        | HMAC signing key (at least 32 bytes)                 |
| `JWTIssuer` / `JWTAudience`        | Issuer / audience of this instance                   |
| `JWTExpiration`                    | Access token lifetime, minutes; also how long a logged-out access token is still accepted by servers that validate it locally |
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
| POST   | `/api/auth/register`                   | none, rate limited      | Body `{ username, email, password }`; creates a user with `Roles:Initial`, returns `{ user, roles, accessToken, refreshToken }` |
| POST   | `/api/auth/login`                      | none, rate limited      | Body `{ username \| email, password }` (exactly one identifier); returns `{ user, roles, accessToken, refreshToken }` |
| POST   | `/api/auth/session`                    | none, rate limited      | Body `{ accessToken?, refreshToken? }`; returns `{ user, roles }` for a valid access token, otherwise rotates the refresh token and also returns the new `accessToken`/`refreshToken` |
| POST   | `/api/auth/logout`                     | authenticated, limited  | Body `{ refreshToken }`; revokes the session of that refresh token; always 204 |
| POST   | `/api/auth/logoutAll`                  | authenticated, limited  | Revokes every session of the caller and changes the security stamp; always 204 |
| POST   | `/api/token/refresh`                   | none                    | Body `{ refreshToken }`; rotates it, returns `{ accessToken, refreshToken }` |
| POST   | `/api/token/validate`                  | none                    | Body `{ accessToken }`; always 200 with `{ valid }` |
| POST   | `/api/manage/assignRole`               | root or manager         | Body `{ userId, role }`; assigns a role from `Roles:Available`, returns `{ userId, roles }` |
| POST   | `/api/manage/removeRole`               | root or manager         | Body `{ userId, role }`; the last root holder cannot lose the root role; returns `{ userId, roles }` |
| GET    | `/api/manage/userRoles?userId=`        | self, root or manager   | Returns `{ userId, roles }` |
| GET    | `/api/manage/hasRole?userId=&role=`    | self, root or manager   | Returns `{ hasRole }` |
| PUT    | `/api/profilePicture`                  | any authenticated user  | Multipart field `file`; replaces the caller's picture, returns its metadata |
| GET    | `/api/profilePicture/{userId}`         | none                    | Image bytes with `ETag`/`Last-Modified`; `If-None-Match` gives 304 |
| DELETE | `/api/profilePicture`                  | any authenticated user  | Deletes the caller's picture; 404 if there is none |
| DELETE | `/api/profilePicture/{userId}`         | root or manager         | Moderation: deletes a user's picture (cannot replace it); managers cannot target root or manager holders; logged |

Profile picture uploads are checked against the `ProfilePicture` section: the format is detected
from the file signature (the client file name and Content-Type are ignored), then the format and
dimensions are validated. Oversized uploads are rejected while reading: 413 from the service, or
400 if the multipart body exceeds the limit before the file reaches it. Pictures are served with
`X-Content-Type-Options: nosniff` and a sandboxing `Content-Security-Policy`.

Invalid request bodies are rejected with 400 and a `ValidationProblemDetails` body.

## Token Model

- **Access token**: JWT with `sub` (user id), `jti`, `ClaimTypes.Name`, `sstamp` (SHA-256 of
  the user's security stamp) and one `ClaimTypes.Role` per role. Validated with the singleton `TokenValidationParameters`
  registered in `Program.cs` (1 minute clock skew). JWT Bearer is the default authentication
  scheme (overriding the cookie defaults set by `AddIdentity`).
- **Refresh token**: 64 random bytes. The client receives the raw value; only its SHA-256 hash
  is stored.
- **Session**: every password login or registration starts a session with a new `SessionId`;
  rotation copies it to the new token, so all tokens rotated from one sign-in share it. One user
  can have several sessions (devices, browsers).
- **Rotation**: the old token is revoked by a conditional `UPDATE` inside a transaction, so of
  several concurrent requests with the same token only one succeeds.
- **Logout** (`/api/auth/logout`): revokes every active token of the session the presented token
  belongs to, even if that token was already rotated (another tab, or a thief who refreshed first).
  The security stamp is kept, so other sessions stay signed in; access tokens of the session stay
  valid until they expire.
- **Logout from all sessions** (`/api/auth/logoutAll`): revokes every active refresh token of the
  user and changes the security stamp.
- **Reuse detection**: presenting a rotated token (one that has a successor) revokes all active
  refresh tokens of its user and changes their security stamp. A token revoked by logout has no
  successor and is only rejected, so a late request from a logged-out client is harmless.
- **Security stamp**: every access token check (JWT Bearer `OnTokenValidated` and
  `/api/token/validate`) compares `sstamp` with the user's current stamp. Role changes, logout
  from all sessions and reuse detection change the stamp, so access tokens issued before them are rejected at once
  (costs one user lookup per authenticated request).

## Request Pipeline (Program.cs order)

`RequestLoggingMiddleware`, OpenAPI, Swagger (Development only) → HttpsRedirection → Routing →
CORS → RateLimiter → Authentication → Authorization → MapControllers.

## Deployment

Step-by-step instructions are in [README.md](README.md). In short, after creating the files in
`instances/` from their templates:

```bash
docker network create shared-network 2>/dev/null || true                 # once per host
docker compose --env-file instances/.env up -d --build                   # server + SQL Server
```

`COMPOSE_PROFILES` in `instances/.env` selects the SQL Server mode: `persistent` (named volume,
restarts with Docker), `test` (no volume, `down` deletes the databases) or empty (external SQL Server).

The stack name is fixed, so a host runs one IdentityServer stack; a second one would need another
project name (`-p`), `AUTH_PORT` and `DB_PORT`.

## Known Issues

Tracked in code with `FIXME:` / `TODO:` (see `AGENTS.md`). Open items:

- Microsoft package versions are 9.0.x while the target framework is `net10.0`.
- `/api/token/refresh` rejects a token with 400, while `/api/auth/session` uses 401.
- `/api/manage/*` answers 400 for an unknown `userId`, while `/api/profilePicture` uses 404.
- Reuse detection does not use `SessionId` yet, so it revokes every session of the user.
- `RefreshToken.TokenHash` is `nvarchar(max)` without an index, so every token lookup scans the table.
- Rate limiting by IP needs `ForwardedHeaders` behind a reverse proxy.
- The `dbcreator` role of `DB_USER` also allows creating databases of other names and dropping
  databases the login owns.
- No cleanup of expired/revoked refresh tokens yet.
- Access tokens are signed with a shared HMAC secret, so any resource server that validates them
  locally can also issue them; RS256/ES256 with a JWKS endpoint is planned.
