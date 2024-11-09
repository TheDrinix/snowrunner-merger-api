namespace SnowrunnerMergerApi.Models.Auth.Google;

public record GoogleCredentials
{
    public string ClientId { get; init; }
    public string ClientSecret { get; init; }
    public string? RedirectUrl { get; init; }
};