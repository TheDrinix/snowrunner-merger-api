using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;

namespace SnowrunnerMergerApi.Services.Interfaces;

public interface IUserService
{
    /// <summary>
    /// Retrieves the current user's session data from the JWT.
    /// </summary>
    /// <returns>JwtData containing user session information.</returns>
    JwtData GetUserSessionData();
    /// <summary>
    /// Retrieves the current user from the database.
    /// </summary>
    /// <returns>The current user.</returns>
    Task<User> GetCurrentUser();
    /// <summary>
    /// Updates the username of the current user.
    /// </summary>
    /// <param name="username">The new username.</param>
    /// <returns>The updated user.</returns>
    Task<User> UpdateUsername(string username);
    /// <summary>
    /// Deletes the current user from the database.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task DeleteUser();
};
