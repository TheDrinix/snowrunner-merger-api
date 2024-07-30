namespace SnowrunnerMergerApi.Models.Saves.Dtos;

public record GroupDto
{
  public Guid Id { get; set; }
  public string Name { get; set; }
  public ICollection<StoredSaveInfo> StoredSaves { get; set; }
  public ICollection<GroupMemberDto> Members { get; set; }
  public Guid OwnerId { get; set; }
  public GroupMemberDto Owner { get; set; }
};