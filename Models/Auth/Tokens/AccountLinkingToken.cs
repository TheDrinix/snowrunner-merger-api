namespace SnowrunnerMergerApi.Models.Auth.Tokens;

public class AccountLinkingToken : UserToken
{
    public string GoogleId { get; set; }
    public Guid UserId { get; set; }
    public User User { get; set; }
}