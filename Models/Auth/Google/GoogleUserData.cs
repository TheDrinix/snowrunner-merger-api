using System.Text.Json.Serialization;

namespace SnowrunnerMergerApi.Models.Auth.Google;

public record GoogleUserData
{
    [JsonPropertyName("id")]
    public string Id { get; set; }
    [JsonPropertyName("email")]
    public string Email { get; set; }
    [JsonPropertyName("verified_email")]
    public bool EmailVerified { get; set; }
    [JsonPropertyName("name")]
    public string Name { get; set; }
    [JsonPropertyName("given_name")]
    public string FirstName { get; set; }
};