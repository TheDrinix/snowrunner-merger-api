namespace SnowrunnerMergerApi.Models.Dtos;

public record LoginDto
{
    public string Email { get; set; }
    public string Password { get; set; }
};