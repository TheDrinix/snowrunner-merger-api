using SnowrunnerMergerApi.Models.Auth;

namespace SnowrunnerMergerApi.Models.Saves;

public class SaveGroup
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public ICollection<StoredSaveInfo> StoredSaves { get; set; }
    public ICollection<User> Members { get; set; }
    public Guid OwnerId { get; set; }
    public User Owner { get; set; }
}