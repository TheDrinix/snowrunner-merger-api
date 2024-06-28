namespace SnowrunnerMergerApi.Models.Dtos;

public record LoginResponseDto
{
    public string AccessToken { get; init; }
    public int ExpiresIn { get; init; }
    public string RefreshToken { get; init; }
    public DateTime RefreshTokenExpiresAt { get; init; }
    public User User { get; init; }
};