-- Creates the application login from DB_USER / DB_PASSWORD, or updates its password.
-- sqlcmd substitutes $(...) with environment variables as plain text, so the values must not contain "'".
-- dbcreator lets the login create its database on the first migration and own it.

DECLARE @login sysname = N'$(DB_USER)';
DECLARE @password nvarchar(128) = N'$(DB_PASSWORD)';
DECLARE @sql nvarchar(max) =
  CASE WHEN SUSER_ID(@login) IS NULL THEN N'CREATE' ELSE N'ALTER' END
  + N' LOGIN ' + QUOTENAME(@login) + N' WITH PASSWORD = ' + QUOTENAME(@password, '''') + N';'
  + N' ALTER SERVER ROLE dbcreator ADD MEMBER ' + QUOTENAME(@login) + N';';

EXEC (@sql);
