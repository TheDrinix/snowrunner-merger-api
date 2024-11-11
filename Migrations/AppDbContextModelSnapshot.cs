﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;
using SnowrunnerMergerApi.Data;

#nullable disable

namespace SnowrunnerMergerApi.Migrations
{
    [DbContext(typeof(AppDbContext))]
    partial class AppDbContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.6")
                .HasAnnotation("Relational:MaxIdentifierLength", 63);

            NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

            modelBuilder.Entity("SaveGroupUser", b =>
                {
                    b.Property<Guid>("JoinedGroupsId")
                        .HasColumnType("uuid");

                    b.Property<Guid>("MembersId")
                        .HasColumnType("uuid");

                    b.HasKey("JoinedGroupsId", "MembersId");

                    b.HasIndex("MembersId");

                    b.ToTable("SaveGroupUser");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Auth.User", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<bool>("EmailConfirmed")
                        .HasColumnType("boolean");

                    b.Property<string>("NormalizedEmail")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<string>("NormalizedUsername")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<byte[]>("PasswordHash")
                        .IsRequired()
                        .HasColumnType("bytea");

                    b.Property<byte[]>("PasswordSalt")
                        .IsRequired()
                        .HasColumnType("bytea");

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Auth.UserSession", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTime>("ExpiresAt")
                        .HasColumnType("timestamp with time zone");

                    b.Property<bool>("IsRevoked")
                        .HasColumnType("boolean");

                    b.Property<byte[]>("RefreshToken")
                        .IsRequired()
                        .HasColumnType("bytea");

                    b.Property<Guid>("UserId")
                        .HasColumnType("uuid");

                    b.HasKey("Id");

                    b.HasIndex("RefreshToken")
                        .IsUnique();

                    b.HasIndex("UserId");

                    b.ToTable("UserSessions");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Auth.UserToken", b =>
                {
                    b.Property<Guid>("UserId")
                        .HasColumnType("uuid");

                    b.Property<string>("Token")
                        .HasColumnType("text");

                    b.Property<int>("Type")
                        .HasColumnType("integer");

                    b.Property<DateTime>("ExpiresAt")
                        .HasColumnType("timestamp with time zone");

                    b.HasKey("UserId", "Token", "Type")
                        .HasName("user_token_pkey");

                    b.ToTable("UserTokens");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Saves.SaveGroup", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<Guid>("OwnerId")
                        .HasColumnType("uuid");

                    b.HasKey("Id");

                    b.HasIndex("OwnerId");

                    b.ToTable("SaveGroups");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Saves.StoredSaveInfo", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<string>("Description")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<Guid>("SaveGroupId")
                        .HasColumnType("uuid");

                    b.Property<int>("SaveNumber")
                        .HasColumnType("integer");

                    b.Property<DateTime>("UploadedAt")
                        .HasColumnType("timestamp with time zone");

                    b.HasKey("Id");

                    b.HasIndex("SaveGroupId");

                    b.ToTable("StoredSaves");
                });

            modelBuilder.Entity("SaveGroupUser", b =>
                {
                    b.HasOne("SnowrunnerMergerApi.Models.Saves.SaveGroup", null)
                        .WithMany()
                        .HasForeignKey("JoinedGroupsId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("SnowrunnerMergerApi.Models.Auth.User", null)
                        .WithMany()
                        .HasForeignKey("MembersId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Auth.UserSession", b =>
                {
                    b.HasOne("SnowrunnerMergerApi.Models.Auth.User", "User")
                        .WithMany("UserSessions")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("User");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Auth.UserToken", b =>
                {
                    b.HasOne("SnowrunnerMergerApi.Models.Auth.User", "User")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("User");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Saves.SaveGroup", b =>
                {
                    b.HasOne("SnowrunnerMergerApi.Models.Auth.User", "Owner")
                        .WithMany("OwnedGroups")
                        .HasForeignKey("OwnerId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Owner");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Saves.StoredSaveInfo", b =>
                {
                    b.HasOne("SnowrunnerMergerApi.Models.Saves.SaveGroup", "SaveGroup")
                        .WithMany("StoredSaves")
                        .HasForeignKey("SaveGroupId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("SaveGroup");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Auth.User", b =>
                {
                    b.Navigation("OwnedGroups");

                    b.Navigation("UserSessions");
                });

            modelBuilder.Entity("SnowrunnerMergerApi.Models.Saves.SaveGroup", b =>
                {
                    b.Navigation("StoredSaves");
                });
#pragma warning restore 612, 618
        }
    }
}
