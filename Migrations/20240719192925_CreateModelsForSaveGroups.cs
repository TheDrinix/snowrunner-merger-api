using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SnowrunnerMergerApi.Migrations
{
    /// <inheritdoc />
    public partial class CreateModelsForSaveGroups : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SaveGroups",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    OwnerId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SaveGroups", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SaveGroups_Users_OwnerId",
                        column: x => x.OwnerId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SaveGroupUser",
                columns: table => new
                {
                    JoinedGroupsId = table.Column<Guid>(type: "uuid", nullable: false),
                    MembersId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SaveGroupUser", x => new { x.JoinedGroupsId, x.MembersId });
                    table.ForeignKey(
                        name: "FK_SaveGroupUser_SaveGroups_JoinedGroupsId",
                        column: x => x.JoinedGroupsId,
                        principalTable: "SaveGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SaveGroupUser_Users_MembersId",
                        column: x => x.MembersId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StoredSaves",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: false),
                    SaveNumber = table.Column<int>(type: "integer", nullable: false),
                    UploadedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    SaveGroupId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StoredSaves", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StoredSaves_SaveGroups_SaveGroupId",
                        column: x => x.SaveGroupId,
                        principalTable: "SaveGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SaveGroups_OwnerId",
                table: "SaveGroups",
                column: "OwnerId");

            migrationBuilder.CreateIndex(
                name: "IX_SaveGroupUser_MembersId",
                table: "SaveGroupUser",
                column: "MembersId");

            migrationBuilder.CreateIndex(
                name: "IX_StoredSaves_SaveGroupId",
                table: "StoredSaves",
                column: "SaveGroupId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SaveGroupUser");

            migrationBuilder.DropTable(
                name: "StoredSaves");

            migrationBuilder.DropTable(
                name: "SaveGroups");
        }
    }
}
