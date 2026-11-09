using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityServer.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenHashIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // TokenService only stores 44-char hashes of random tokens, so neither check should fire on real data.
            migrationBuilder.Sql(@"
IF EXISTS (SELECT 1 FROM RefreshTokens WHERE LEN(TokenHash) > 44)
    THROW 50000, 'RefreshTokens contains TokenHash values longer than 44 characters; remove them before applying AddRefreshTokenHashIndex.', 1;
IF EXISTS (SELECT TokenHash FROM RefreshTokens GROUP BY TokenHash HAVING COUNT(*) > 1)
    THROW 50000, 'RefreshTokens contains duplicate TokenHash values; remove them before applying AddRefreshTokenHashIndex.', 1;");

            migrationBuilder.AlterColumn<string>(
                name: "TokenHash",
                table: "RefreshTokens",
                type: "nvarchar(44)",
                maxLength: 44,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_TokenHash",
                table: "RefreshTokens",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RefreshTokens_TokenHash",
                table: "RefreshTokens");

            migrationBuilder.AlterColumn<string>(
                name: "TokenHash",
                table: "RefreshTokens",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(44)",
                oldMaxLength: 44);
        }
    }
}
