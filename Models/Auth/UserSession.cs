using Microsoft.EntityFrameworkCore;

namespace SnowrunnerMergerApi.Models;

[Index(nameof(RefreshToken), IsUnique = true)]
public class UserSession
{
    public int Id;
    public byte[] RefreshToken;
    public DateTime ExpiresAt;
    
    public Guid UserId;
    public User User;
}