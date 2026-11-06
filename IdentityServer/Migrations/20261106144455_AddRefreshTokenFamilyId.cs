using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityServer.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenFamilyId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "FamilyId",
                table: "RefreshTokens",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Backfills existing tokens: every chain root (a token that is no other token's replacement) starts a family
            // keyed by its own Id, and the family is passed down the ReplacedByTokenHash links. A chain gets one
            // step per rotation, so the default recursion limit of 100 is lifted.
            migrationBuilder.Sql(@"
WITH Chain AS (
    SELECT rt.Id, rt.ReplacedByTokenHash, rt.Id AS FamilyId
    FROM RefreshTokens rt
    WHERE NOT EXISTS (SELECT 1 FROM RefreshTokens parent WHERE parent.ReplacedByTokenHash = rt.TokenHash)
    UNION ALL
    SELECT child.Id, child.ReplacedByTokenHash, Chain.FamilyId
    FROM RefreshTokens child
    INNER JOIN Chain ON child.TokenHash = Chain.ReplacedByTokenHash
)
UPDATE rt
SET FamilyId = Chain.FamilyId
FROM RefreshTokens rt
INNER JOIN Chain ON rt.Id = Chain.Id
OPTION (MAXRECURSION 0);");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens",
                column: "FamilyId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_FamilyId",
                table: "RefreshTokens");

            migrationBuilder.DropColumn(
                name: "FamilyId",
                table: "RefreshTokens");
        }
    }
}
