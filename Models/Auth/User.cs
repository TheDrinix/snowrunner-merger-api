using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Models.Saves;

namespace SnowrunnerMergerApi.Models.Auth;

[Index(nameof(NormalizedEmail))]
[Index(nameof(Email), IsUnique = true)]
[Index(nameof(GoogleId), IsUnique = true)]
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
    [JsonIgnore]
    public string? GoogleId { get; set; }
    public DateTime CreatedAt { get; set; }
    [JsonIgnore]
    public List<UserSession> UserSessions { get; set; }
    [JsonIgnore]
    public List<SaveGroup> JoinedGroups { get; set; }
    [JsonIgnore]
    public List<SaveGroup> OwnedGroups { get; set; }
}