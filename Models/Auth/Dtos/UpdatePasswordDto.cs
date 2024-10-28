namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record UpdatePasswordDto
{
    public string CurrentPassword { get; init; }
    public string NewPassword { get; init; }
};