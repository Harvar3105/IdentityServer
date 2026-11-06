using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityServer.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenSessionId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "SessionId",
                table: "RefreshTokens",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Backfills existing tokens: every chain root (a token that is no other token's replacement) starts a session
            // keyed by its own Id, and the session is passed down the ReplacedByTokenHash links. A chain gets one
            // step per rotation, so the default recursion limit of 100 is lifted.
            migrationBuilder.Sql(@"
WITH Chain AS (
    SELECT rt.Id, rt.ReplacedByTokenHash, rt.Id AS SessionId
    FROM RefreshTokens rt
    WHERE NOT EXISTS (SELECT 1 FROM RefreshTokens parent WHERE parent.ReplacedByTokenHash = rt.TokenHash)
    UNION ALL
    SELECT child.Id, child.ReplacedByTokenHash, Chain.SessionId
    FROM RefreshTokens child
    INNER JOIN Chain ON child.TokenHash = Chain.ReplacedByTokenHash
)
UPDATE rt
SET SessionId = Chain.SessionId
FROM RefreshTokens rt
INNER JOIN Chain ON rt.Id = Chain.Id
OPTION (MAXRECURSION 0);");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_SessionId",
                table: "RefreshTokens",
                column: "SessionId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_SessionId",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "RefreshTokens");
        }
    }
}
