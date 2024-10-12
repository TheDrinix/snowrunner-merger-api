namespace SnowrunnerMergerApi.Models.Auth;

public class PasswordResetToken
{
    public string Token { get; set; }
    public Guid UserId { get; set; }
    public User User { get; set; }
    public DateTime ExpiresAt { get; set; }
}