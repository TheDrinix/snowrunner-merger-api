namespace SnowrunnerMergerApi.Models;

public record RefreshTokenData
{
    public User User { get; init; }
    public string RefreshToken { get; init; }
    public DateTime ExpiresAt { get; init; }
};