namespace SnowrunnerMergerApi.Models.Auth;

public enum TokenType
{
    AccountConfirmation,
    PasswordReset
}

public class UserToken
{
    public Guid UserId { get; set; }
    public User User { get; set; }
    public string Token { get; set; }
    public DateTime ExpiresAt { get; set; }
    public TokenType Type { get; set; }
}