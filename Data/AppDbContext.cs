using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ValueGeneration;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Tokens;
using SnowrunnerMergerApi.Models.Saves;

namespace SnowrunnerMergerApi.Data;

public class AppDbContext(DbContextOptions<AppDbContext> opt) : DbContext(opt)
{
    public DbSet<User> Users { get; set; }
    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<StoredSaveInfo> StoredSaves { get; set; }
    public DbSet<SaveGroup> SaveGroups { get; set; }
    public DbSet<UserToken> UserTokens { get; set; }
    
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
            .Entity<UserToken>()
            .HasDiscriminator<string>("TokenType")
            .HasValue<AccountConfirmationToken>("AccountConfirmation")
            .HasValue<PasswordResetToken>("PasswordReset")
            .HasValue<AccountLinkingToken>("AccountLinking")
            .HasValue<AccountCompletionToken>("AccountCompletion");
        
        modelBuilder
            .Entity<AccountLinkingToken>()
            .HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .HasPrincipalKey(u => u.Id)
            .OnDelete(DeleteBehavior.Cascade);
        
        modelBuilder
            .Entity<PasswordResetToken>()
            .HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .HasPrincipalKey(u => u.Id)
            .OnDelete(DeleteBehavior.Cascade);
        
        modelBuilder
            .Entity<AccountConfirmationToken>()
            .HasOne(t => t.User)
            .WithMany()
            .HasForeignKey(t => t.UserId)
            .HasPrincipalKey(u => u.Id)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder
            .Entity<UserSession>()
            .Property(s => s.HasLongLivedRefreshToken)
            .HasDefaultValue(false);
    }
}