using SnowrunnerMergerApi.Models.Saves;

namespace SnowrunnerMergerApi.Services;

public interface IGroupsService
{
    Task<SaveGroup?> GetGroup(Guid groupId);
    Task<SaveGroup?> GetGroupData(Guid groupId, Guid userId);
    Task<ICollection<SaveGroup>> GetUserGroups(Guid userId);
    Task<SaveGroup> CreateGroup(string name, Guid userId);
    Task<SaveGroup> JoinGroup(Guid groupId, Guid userId);
    Task LeaveGroup(Guid groupId);
    Task RemoveGroup(Guid groupId);
}