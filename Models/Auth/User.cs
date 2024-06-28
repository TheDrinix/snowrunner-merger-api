using System.Text.Json.Serialization;

namespace SnowrunnerMergerApi.Models;

public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; }
    [JsonIgnore]
    public string NormalizedUsername { get; set; }
    public string Email { get; set; }
    [JsonIgnore]
    public string NormalizedEmail { get; set; }
    [JsonIgnore]
    public byte[] PasswordHash { get; set; }
    [JsonIgnore]
    public byte[] PasswordSalt { get; set; }
    [JsonIgnore]
    public bool EmailConfirmed { get; set; }
    public DateTime CreatedAt { get; set; }
    
    public List<UserSession> UserSessions { get; set; }
}