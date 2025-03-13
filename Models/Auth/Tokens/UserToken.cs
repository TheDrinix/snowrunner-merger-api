using Microsoft.EntityFrameworkCore;

namespace SnowrunnerMergerApi.Models.Auth.Tokens;

[Index(nameof(Token), IsUnique = true)]
public class UserToken
{
    public int Id { get; set; }
    public string Token { get; set; }
    public DateTime ExpiresAt { get; set; }
}