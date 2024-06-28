namespace SnowrunnerMergerApi.Models;

public record JwtData
{
    public Guid Id { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
}