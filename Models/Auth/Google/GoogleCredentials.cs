namespace SnowrunnerMergerApi.Models.Auth.Google;

public record GoogleCredentials
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
};