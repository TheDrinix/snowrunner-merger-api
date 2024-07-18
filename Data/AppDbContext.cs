using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ValueGeneration;
using SnowrunnerMergerApi.Models.Auth;

namespace SnowrunnerMergerApi.Data;

public class AppDbContext : DbContext
{
    
    public DbSet<User> Users { get; set; }
    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<UserConfirmationToken> UserConfirmationTokens { get; set; }
    public AppDbContext(DbContextOptions<AppDbContext> opt) : base(opt)
    {
        
    }

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
    }
}