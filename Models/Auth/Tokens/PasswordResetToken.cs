namespace SnowrunnerMergerApi.Models.Auth.Tokens;

public class PasswordResetToken : UserToken
{
    public Guid UserId { get; set; }
    public User User { get; set; }
}