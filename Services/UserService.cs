using System.Net;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;

namespace SnowrunnerMergerApi.Services;

public interface IUserService
{
    JwtData GetUserSessionData();
    Task<User> GetCurrentUser();
    Task<User> UpdateUsername(string username);
    Task DeleteUser();
};

public class UserService(
    IHttpContextAccessor httpContextAccessor,
    ILogger<UserService> logger,
    AuthService authService,
    AppDbContext dbContext
    ) : IUserService
{
    
    public JwtData GetUserSessionData()
    {
        var principal = httpContextAccessor.HttpContext?.User;
        
        var id = principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        var username = principal?.FindFirstValue(ClaimTypes.Name);
        var email = principal?.FindFirstValue(ClaimTypes.Email);
        var sessionId = principal?.FindFirstValue(ClaimTypes.PrimarySid);

        if (id is null || username is null || email is null || sessionId is null)
        {
            logger.LogError("User session data not found");
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        return new JwtData
        {
            Id = Guid.Parse(id),
            Username = username,
            Email = email,
            SessionId = Guid.Parse(sessionId)
        };
    }

    public async Task<User> GetCurrentUser()
    {
        var userData = GetUserSessionData();
        
        var user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.Id == userData.Id);
        
        if (user is null)
        {
            logger.LogError("User not found");
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        
        return user;
    }

    public async Task<User> UpdateUsername(string username)
    {
        var user = await GetCurrentUser();
        
        user.Username = username;
        
        dbContext.Update(user);
        await dbContext.SaveChangesAsync();

        return user;
    }

    public async Task DeleteUser()
    {
        await authService.Logout();
        
        var user = await GetCurrentUser();
        
        dbContext.Users.Remove(user);
        
        await dbContext.SaveChangesAsync();
    }
}