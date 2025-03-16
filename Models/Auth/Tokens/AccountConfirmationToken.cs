namespace SnowrunnerMergerApi.Models.Auth.Tokens;

public class AccountConfirmationToken : UserToken
{
    public Guid UserId { get;set; }
    public User User { get; set; }
}