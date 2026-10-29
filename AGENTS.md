# Agent Guidelines

This repository is a reusable authentication and authorization server: it manages user
authentication data and the token lifecycle. It is single-tenant: one Docker image is deployed
as a separate container per client project, each with its own database and configuration.
Do not add per-project (tenant) scoping to the code; per-project differences belong in configuration.
See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for the layout, configuration and API.

## Rules

1. All comments, tags and documentation must be written in English.
2. Do not comment obvious parts of the code whose logic is self-describing.
3. When a bug, error, inconsistency or vulnerability is found, mark that part of the code
   with a comment tagged `FIXME:`.
   ```csharp
   // FIXME: Raw refresh token is discarded and its hash is returned to the client.
   ```
4. Mark places planned for future implementation, or that require a further decision,
   with a comment tagged `TODO:`.
   ```csharp
   // TODO: Add account lockout after repeated failed sign-in attempts.
   ```
5. Use descriptive names. Avoid names that are ambiguous.
