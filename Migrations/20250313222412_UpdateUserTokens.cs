using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace SnowrunnerMergerApi.Migrations
{
    /// <inheritdoc />
    public partial class UpdateUserTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM \"UserTokens\"", true);
            
            migrationBuilder.DropPrimaryKey(
                name: "user_token_pkey",
                table: "UserTokens");

            migrationBuilder.RenameColumn(
                name: "Type",
                table: "UserTokens",
                newName: "Id");

            migrationBuilder.AlterColumn<Guid>(
                name: "UserId",
                table: "UserTokens",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AlterColumn<int>(
                name: "Id",
                table: "UserTokens",
                type: "integer",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "integer")
                .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn);

            migrationBuilder.AddColumn<string>(
                name: "AccountCompletionToken_GoogleId",
                table: "UserTokens",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AccountConfirmationToken_UserId",
                table: "UserTokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AccountLinkingToken_UserId",
                table: "UserTokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Email",
                table: "UserTokens",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GoogleId",
                table: "UserTokens",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TokenType",
                table: "UserTokens",
                type: "character varying(21)",
                maxLength: 21,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_UserTokens",
                table: "UserTokens",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_UserTokens_AccountConfirmationToken_UserId",
                table: "UserTokens",
                column: "AccountConfirmationToken_UserId");

            migrationBuilder.CreateIndex(
                name: "IX_UserTokens_AccountLinkingToken_UserId",
                table: "UserTokens",
                column: "AccountLinkingToken_UserId");

            migrationBuilder.CreateIndex(
                name: "IX_UserTokens_Token",
                table: "UserTokens",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserTokens_UserId",
                table: "UserTokens",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_UserTokens_Users_AccountConfirmationToken_UserId",
                table: "UserTokens",
                column: "AccountConfirmationToken_UserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserTokens_Users_AccountLinkingToken_UserId",
                table: "UserTokens",
                column: "AccountLinkingToken_UserId",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_UserTokens_Users_AccountConfirmationToken_UserId",
                table: "UserTokens");

            migrationBuilder.DropForeignKey(
                name: "FK_UserTokens_Users_AccountLinkingToken_UserId",
                table: "UserTokens");

            migrationBuilder.DropPrimaryKey(
                name: "PK_UserTokens",
                table: "UserTokens");

            migrationBuilder.DropIndex(
                name: "IX_UserTokens_AccountConfirmationToken_UserId",
                table: "UserTokens");

            migrationBuilder.DropIndex(
                name: "IX_UserTokens_AccountLinkingToken_UserId",
                table: "UserTokens");

            migrationBuilder.DropIndex(
                name: "IX_UserTokens_Token",
                table: "UserTokens");

            migrationBuilder.DropIndex(
                name: "IX_UserTokens_UserId",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "AccountCompletionToken_GoogleId",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "AccountConfirmationToken_UserId",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "AccountLinkingToken_UserId",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "Email",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "GoogleId",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "TokenType",
                table: "UserTokens");

            migrationBuilder.RenameColumn(
                name: "Id",
                table: "UserTokens",
                newName: "Type");

            migrationBuilder.AlterColumn<Guid>(
                name: "UserId",
                table: "UserTokens",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AlterColumn<int>(
                name: "Type",
                table: "UserTokens",
                type: "integer",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "integer")
                .OldAnnotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn);

            migrationBuilder.AddPrimaryKey(
                name: "user_token_pkey",
                table: "UserTokens",
                columns: new[] { "UserId", "Token", "Type" });
        }
    }
}
