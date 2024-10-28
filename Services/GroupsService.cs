using System.Net;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Services.Interfaces;

namespace SnowrunnerMergerApi.Services;

public class GroupsService(
    ILogger<GroupsService> logger, 
    AppDbContext dbContext,
    IUserService userService,
    ISavesService savesService) : IGroupsService
{
    /// <summary>
    /// Retrieves a SaveGroup by its unique identifier with stored saves included.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <returns>The SaveGroup if found; otherwise, null.</returns>
    public async Task<SaveGroup?> GetGroup(Guid groupId)
    {
        return await dbContext.SaveGroups
            .Include(g => g.Owner)
            .Include(g => g.Members)
            .Include(g => g.StoredSaves)
            .FirstOrDefaultAsync(g => g.Id == groupId);
    }
    
    /// <summary>
    ///     Retrieves a SaveGroup with stored saves included by its unique identifier and checks if the user is a member of the group.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>The SaveGroup if found and the user is a member; otherwise, null.</returns>
    public async Task<SaveGroup?> GetGroupData(Guid groupId, Guid userId)
    {
        var group = await GetGroup(groupId);
        
        if (group is null || group.Members.All(m => m.Id != userId)) return null;
        
        return group;
    }
    
    /// <summary>
    ///     Retrieves all groups the user is a member of.
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>A collection of SaveGroup objects.</returns>
    public async Task<ICollection<SaveGroup>> GetUserGroups(Guid userId)
    {
        var user = await dbContext.Users
            .Include(u => u.JoinedGroups)
            .ThenInclude(g => g.Members)
            .Include(u => u.JoinedGroups)
            .ThenInclude(g => g.Owner)
            .FirstOrDefaultAsync(u => u.Id == userId);

        return user?.JoinedGroups ?? [];
    }

    /// <summary>
    ///     Creates a new group with the specified name and the user as the owner.
    /// </summary>
    /// <param name="name">The name of the group.</param>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>The newly created SaveGroup object.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.Unauthorized (401): The user is not found.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Forbidden (403): The user already owns 4 groups.
    ///         </item>
    ///     </list> 
    /// </exception>
    public async Task<SaveGroup> CreateGroup(string name, Guid userId)
    {
        var user = await dbContext.Users
            .Include(u => u.OwnedGroups)
            .IgnoreAutoIncludes()
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user is null) throw new HttpResponseException(HttpStatusCode.Unauthorized);
        
        if (user.OwnedGroups.Count >= 4) throw new HttpResponseException(HttpStatusCode.Forbidden, "User already owns 4 groups");
        
        var group = new SaveGroup()
        {
            Name = name,
            Owner = user,
            Members = new List<User>() { user }
        };
        
        await dbContext.SaveGroups.AddAsync(group);
        await dbContext.SaveChangesAsync();
        
        return group;
    }
    
    /// <summary>
    /// Adds the current user to the specified group.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <returns>The updated SaveGroup object.</returns>
    /// <exception cref="HttpResponseException">
    /// Thrown with different an HttpStatusCode.NotFound (404) when the group is not found.
    /// </exception>
    public async Task<SaveGroup> JoinGroup(Guid groupId, Guid userId)
    {
        var group = await dbContext.SaveGroups
            .Include(g => g.Members)
            .FirstOrDefaultAsync(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");

        var user = await userService.GetCurrentUser();
        
        group.Members.Add(user);
        
        dbContext.SaveGroups.Update(group);
        await dbContext.SaveChangesAsync();
        
        return group;
    }
    
    /// <summary>
    ///     Removes the current user from the specified group.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <exception cref="HttpResponseException">
    ///     Thrown with an HttpStatusCode.NotFound (404) when the group is not found.
    /// </exception>
    public async Task LeaveGroup(Guid groupId)
    {
        var group = await dbContext.SaveGroups
            .Include(g => g.Members)
            .FirstOrDefaultAsync(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");
        
        var user = await userService.GetCurrentUser();
        
        group.Members.Remove(user);
        
        dbContext.SaveGroups.Update(group);
        await dbContext.SaveChangesAsync();
    }
    
    /// <summary>
    ///     Removes the specified group and all its stored saves.
    /// </summary>
    /// <param name="groupId">The unique identifier of the group.</param>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.NotFound (404): The group is not found.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Forbidden (403): The user is not the owner of the group.
    ///         </item>
    ///     </list>
    /// </exception>
    public async Task RemoveGroup(Guid groupId)
    {
        var userSession = userService.GetUserSessionData();
        
        var group = await GetGroupData(groupId, userSession.Id);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");
        
        if (group.Owner.Id != userSession.Id) throw new HttpResponseException(HttpStatusCode.Forbidden, "You don't own this group");
        
        foreach (var save in group.StoredSaves)
        {
            await savesService.RemoveSave(save);
        }
        
        dbContext.SaveGroups.Remove(group);
        await dbContext.SaveChangesAsync();
    }
}