namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record RefreshDto
{
    public string? Token { get; init; }
};