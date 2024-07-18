namespace SnowrunnerMergerApi.Models.Auth;

public class UserConfirmationToken
{
    public Guid UserId { get; set; }
    public User User { get; set; }
    public string Token { get; set; }
    public DateTime ExpiresAt { get; set; }
}