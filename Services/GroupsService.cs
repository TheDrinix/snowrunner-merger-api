using System.Net;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;
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

public class GroupsService(ILogger<GroupsService> logger, AppDbContext dbContext, IAuthService authService, ISavesService savesService) : IGroupsService
{
    private readonly ILogger<GroupsService> _logger = logger;

    public async Task<SaveGroup?> GetGroup(Guid groupId)
    {
        return await dbContext.SaveGroups
            .Include(g => g.Owner)
            .Include(g => g.Members)
            .Include(g => g.StoredSaves)
            .FirstOrDefaultAsync(g => g.Id == groupId);
    }

    public async Task<SaveGroup?> GetGroupData(Guid groupId, Guid userId)
    {
        var group = await GetGroup(groupId);
        
        if (group is null || group.Members.All(m => m.Id != userId)) return null;
        
        return group;
    }

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

    public async Task<SaveGroup> CreateGroup(string name, Guid userId)
    {
        var user = await dbContext.Users
            .Include(u => u.OwnedGroups)
            .IgnoreAutoIncludes()
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user is null) throw new HttpResponseException(HttpStatusCode.Unauthorized);
        
        if (user.OwnedGroups.Count >= 4) throw new HttpResponseException(HttpStatusCode.BadRequest, "User already owns 4 groups");
        
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

    public async Task<SaveGroup> JoinGroup(Guid groupId, Guid userId)
    {
        var group = await dbContext.SaveGroups
            .Include(g => g.Members)
            .FirstOrDefaultAsync(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");

        var user = await authService.GetCurrentUser();
        
        group.Members.Add(user);
        
        dbContext.SaveGroups.Update(group);
        await dbContext.SaveChangesAsync();
        
        return group;
    }
    
    public async Task LeaveGroup(Guid groupId)
    {
        var group = await dbContext.SaveGroups
            .Include(g => g.Members)
            .FirstOrDefaultAsync(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");
        
        var user = await authService.GetCurrentUser();
        
        group.Members.Remove(user);
        
        dbContext.SaveGroups.Update(group);
        await dbContext.SaveChangesAsync();
    }

    public async Task RemoveGroup(Guid groupId)
    {
        var userSession = authService.GetUserSessionData();
        
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