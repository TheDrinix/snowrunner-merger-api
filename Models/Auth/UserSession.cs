using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace SnowrunnerMergerApi.Models.Auth;

[Index(nameof(RefreshToken), IsUnique = true)]
[PrimaryKey(nameof(Id))]
public class UserSession
{
    public int Id { get; set; }
    public byte[] RefreshToken { get; set; }
    public DateTime ExpiresAt { get; set; }
    
    public Guid UserId { get; set; }
    public User User { get; set; }
}