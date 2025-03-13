namespace SnowrunnerMergerApi.Models.Auth.Tokens;

public class AccountCompletionToken : UserToken
{
    public string GoogleId { get; set; }
    public string Email { get; set; }
}