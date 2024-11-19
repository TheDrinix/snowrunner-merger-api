using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace SnowrunnerMergerApi.Models.Auth;

[Index(nameof(RefreshToken), IsUnique = true)]
[PrimaryKey(nameof(Id))]
public class UserSession
{
    public Guid Id { get; set; }
    public byte[] RefreshToken { get; set; }
    public bool HasLongLivedRefreshToken { get; set; } = false;
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public Guid UserId { get; set; }
    public User User { get; set; }
}