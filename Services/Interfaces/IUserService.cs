using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Auth;

namespace SnowrunnerMergerApi.Services.Interfaces;

public interface IUserService
{
    /// <summary>
    /// Retrieves the current user's session data from the JWT.
    /// </summary>
    /// <returns>JwtData containing user session information.</returns>
    /// <exception cref="HttpResponseException">Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) when user session data is not found.</exception>
    JwtData GetUserSessionData();
    /// <summary>
    /// Retrieves the current user from the database.
    /// </summary>
    /// <returns>The current user.</returns>
    /// <exception cref="HttpResponseException">Thrown with an HTTP status code of HttpStatusCode.Unauthorized (401) when the user session data is not found.</exception>
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
