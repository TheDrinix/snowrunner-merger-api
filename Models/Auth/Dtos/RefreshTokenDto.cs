namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record RefreshTokenDto
{
    public string Token { get; init; }
    public DateTime ExpiresAt { get; init; }
};