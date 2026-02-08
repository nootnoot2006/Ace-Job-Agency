using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ace_Job_Agency.Migrations
{
    /// <inheritdoc />
    public partial class AddLastPasswordChangedAt : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastPasswordChangedAt",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastPasswordChangedAt",
                table: "AspNetUsers");
        }
    }
}
