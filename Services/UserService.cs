using System.Net;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Services.Interfaces;

namespace SnowrunnerMergerApi.Services;

/// <summary>
/// Service for managing user-related operations.
/// </summary>
public class UserService(
    IHttpContextAccessor httpContextAccessor,
    ILogger<UserService> logger,
    IAuthService authService,
    AppDbContext dbContext
    ) : IUserService
{
    /// <summary>
    /// Retrieves the current user's session data from the JWT.
    /// </summary>
    /// <returns>JwtData containing user session information.</returns>
    /// <exception cref="HttpResponseException">Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) when user session data is not found.</exception>
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

    /// <summary>
    /// Retrieves the current user from the database.
    /// </summary>
    /// <returns>The current user.</returns>
    /// <exception cref="HttpResponseException">Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) when the user session data is not found.</exception>
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

    /// <summary>
    /// Updates the username of the current user.
    /// </summary>
    /// <param name="username">The new username.</param>
    /// <returns>The updated user.</returns>
    public async Task<User> UpdateUsername(string username)
    {
        var user = await GetCurrentUser();
        
        user.Username = username;
        
        dbContext.Update(user);
        await dbContext.SaveChangesAsync();

        return user;
    }

    /// <summary>
    /// Deletes the current user from the database.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task DeleteUser()
    {
        await authService.Logout();
        
        var user = await GetCurrentUser();
        
        dbContext.Users.Remove(user);
        
        await dbContext.SaveChangesAsync();
    }
}