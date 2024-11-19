namespace SnowrunnerMergerApi.Models.Auth;

public record RefreshTokenData
{
    public string Token { get; init; }
    public UserSession Session { get; init; }
};