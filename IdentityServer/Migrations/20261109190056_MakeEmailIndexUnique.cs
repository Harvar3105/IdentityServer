using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityServer.Migrations
{
    /// <inheritdoc />
    public partial class MakeEmailIndexUnique : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Duplicates cannot be merged automatically: the accounts may belong to different people.
            migrationBuilder.Sql(@"
IF EXISTS (
    SELECT NormalizedEmail FROM AspNetUsers
    WHERE NormalizedEmail IS NOT NULL
    GROUP BY NormalizedEmail
    HAVING COUNT(*) > 1)
    THROW 50000, 'AspNetUsers contains users with duplicate emails; resolve them before applying MakeEmailIndexUnique. Find them with: SELECT NormalizedEmail, COUNT(*) FROM AspNetUsers GROUP BY NormalizedEmail HAVING COUNT(*) > 1', 1;");

            migrationBuilder.DropIndex(
                name: "EmailIndex",
                table: "AspNetUsers");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail",
                unique: true,
                filter: "[NormalizedEmail] IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "EmailIndex",
                table: "AspNetUsers");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");
        }
    }
}
