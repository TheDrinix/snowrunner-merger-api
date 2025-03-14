namespace SnowrunnerMergerApi.Models.Auth.Dtos;

public record FinishAccountSetupDto
{
    public string CompletionToken { get; init; }
    public string Username { get; init; }
    public string Password { get; init; }
};