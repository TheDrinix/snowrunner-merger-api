using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ValueGeneration;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Saves;

namespace SnowrunnerMergerApi.Data;

public class AppDbContext(DbContextOptions<AppDbContext> opt) : DbContext(opt)
{
    public DbSet<User> Users { get; set; }
    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<UserConfirmationToken> UserConfirmationTokens { get; set; }
    public DbSet<StoredSaveInfo> StoredSaves { get; set; }
    public DbSet<SaveGroup> SaveGroups { get; set; }
    public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder
            .Entity<User>()
            .Property(u => u.Id)
            .HasValueGenerator<GuidValueGenerator>();

        modelBuilder
            .Entity<UserSession>()
            .Property(s => s.Id)
            .HasValueGenerator<GuidValueGenerator>();
        
        modelBuilder
            .Entity<UserSession>()
            .HasOne(s => s.User)
            .WithMany(u => u.UserSessions)
            .HasForeignKey(s => s.UserId)
            .HasPrincipalKey(u => u.Id)
            .OnDelete(DeleteBehavior.Cascade);
        
        modelBuilder
            .Entity<UserConfirmationToken>()
            .HasKey(t => new {t.UserId, t.Token})
            .HasName("user_confirmation_token_pkey");
        
        modelBuilder
            .Entity<UserConfirmationToken>()
            .HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .HasPrincipalKey(u => u.Id)
            .OnDelete(DeleteBehavior.Cascade);
        
        modelBuilder
            .Entity<SaveGroup>()
            .Property(g => g.Id)
            .HasValueGenerator<GuidValueGenerator>();
        
        modelBuilder
            .Entity<StoredSaveInfo>()
            .Property(s => s.Id)
            .HasValueGenerator<GuidValueGenerator>();
        
        modelBuilder.Entity<SaveGroup>()
            .HasOne<User>(g => g.Owner)
            .WithMany(u => u.OwnedGroups)
            .HasForeignKey(g => g.OwnerId)
            .HasPrincipalKey(u => u.Id)
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<SaveGroup>()
            .HasMany<User>(g => g.Members)
            .WithMany(u => u.JoinedGroups);

        modelBuilder
            .Entity<PasswordResetToken>()
            .HasKey(t => new { t.UserId, t.Token })
            .HasName("password_reset_token_pkey");
        
        modelBuilder
            .Entity<PasswordResetToken>()
            .HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .HasPrincipalKey(u => u.Id)
            .OnDelete(DeleteBehavior.Cascade);
    }
}