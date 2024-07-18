namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record LoginResponseDto
{
    public string AccessToken { get; init; }
    public int ExpiresIn { get; init; }
    public User User { get; init; }
};