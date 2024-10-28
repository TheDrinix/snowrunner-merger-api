using SnowrunnerMergerApi.Models.Saves;

namespace SnowrunnerMergerApi.Services.Interfaces;

public interface IGroupsService
{
    /// <summary>
    /// Retrieves a SaveGroup by its unique identifier with stored saves included.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <returns>The SaveGroup if found; otherwise, null.</returns>
    Task<SaveGroup?> GetGroup(Guid groupId);
    /// <summary>
    ///     Retrieves a SaveGroup with stored saves included by its unique identifier and checks if the user is a member of the group.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>The SaveGroup if found and the user is a member; otherwise, null.</returns>
    Task<SaveGroup?> GetGroupData(Guid groupId, Guid userId);
    /// <summary>
    ///     Retrieves all groups the user is a member of.
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>A collection of SaveGroup objects.</returns>
    Task<ICollection<SaveGroup>> GetUserGroups(Guid userId);
    /// <summary>
    ///     Creates a new group with the specified name and the user as the owner.
    /// </summary>
    /// <param name="name">The name of the group.</param>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>The newly created SaveGroup object.</returns>
    Task<SaveGroup> CreateGroup(string name, Guid userId);
    /// <summary>
    /// Adds the current user to the specified group.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>The updated SaveGroup object.</returns>
    Task<SaveGroup> JoinGroup(Guid groupId, Guid userId);
    /// <summary>
    ///     Removes the current user from the specified group.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    Task LeaveGroup(Guid groupId);
    /// <summary>
    ///     Removes the specified group and all its stored saves.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    Task RemoveGroup(Guid groupId);
}