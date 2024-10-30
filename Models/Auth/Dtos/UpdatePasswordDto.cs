namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record UpdatePasswordDto
{
    public string CurrentPassword { get; init; } = String.Empty;
    public string NewPassword { get; init; }
};