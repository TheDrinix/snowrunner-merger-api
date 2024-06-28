using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ValueGeneration;
using SnowrunnerMergerApi.Models;

namespace SnowrunnerMergerApi.Data;

public class AppDbContext : DbContext
{
    
    public DbSet<User> Users { get; set; }
    public DbSet<UserSession> UserSessions { get; set; }
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
    }
}